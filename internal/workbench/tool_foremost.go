// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// auditForemost carves bounded original byte ranges without decoding payloads.
func auditForemost(ctx context.Context, req ToolRequest) (*Report, error) {
	if req.RunEngine || req.Target != "" {
		return nil, fmt.Errorf("Foremost recovery accepts offline bytes only; engine execution and live targets are unsupported")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	if err := checkInput(data); err != nil {
		return nil, err
	}
	r := newReport("foremost", "Offline structural file recovery completed.", data)
	r.gap("Only PNG chunk framing/checksums, GIF block framing, uncompressed BMP bounds and PCM WAV chunk framing are checked. Payloads are not decoded; structural validity does not prove usability, authenticity or safety.")
	r.gap("No JPEG, PDF, ZIP, deleted-filesystem reconstruction, disk access, archive extraction or file execution. Artifact offsets and lengths reference the original supplied bytes.")
	attempts, budget := 0, 4*MaxInput
	for offset := 0; offset < len(data); offset++ {
		if offset%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		tail := data[offset:]
		format := ""
		switch {
		case bytes.HasPrefix(tail, []byte("\x89PNG\r\n\x1a\n")):
			format = "png"
		case bytes.HasPrefix(tail, []byte("GIF87a")), bytes.HasPrefix(tail, []byte("GIF89a")):
			format = "gif"
		case bytes.HasPrefix(tail, []byte("BM")):
			format = "bmp"
		case len(tail) >= 12 && string(tail[:4]) == "RIFF" && string(tail[8:12]) == "WAVE":
			format = "wav"
		}
		if format == "" {
			continue
		}
		attempts++
		if attempts > 256 || budget <= 0 {
			r.Limited = true
			r.gap("Recovery stopped at the 256-header or 32 MiB structural-work budget.")
			break
		}
		length := 0
		switch format {
		case "png":
			length = foremostPNG(ctx, tail, &budget)
		case "gif":
			length = foremostGIF(ctx, tail, &budget)
		case "bmp":
			length = foremostBMP(tail)
		case "wav":
			length = foremostWAV(ctx, tail, &budget)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if length == 0 {
			r.observe("rejected file header", fmt.Sprintf("offset-%d", offset), format+": truncated, unsupported or structurally inconsistent")
			continue
		}
		if len(r.Artifacts) == 32 {
			r.Limited = true
			r.gap("More than 32 structurally checked files were found; remaining candidates were omitted.")
			break
		}
		name := fmt.Sprintf("recovered-%d.%s", offset, format)
		r.Artifacts = append(r.Artifacts, Artifact{Name: name, Offset: offset, Length: length})
		r.observe("structural recovery candidate", name, fmt.Sprintf("offset %d; %d bytes; payload not decoded", offset, length))
		offset += length - 1
	}
	if budget <= 0 {
		r.Limited = true
		r.gap("The 32 MiB structural-work budget was exhausted.")
	}
	r.Summary = fmt.Sprintf("Recovered %d structurally checked file byte ranges from %d bytes.", len(r.Artifacts), len(data))
	return r, nil
}

func foremostPNG(ctx context.Context, data []byte, budget *int) int {
	pos, idat := 8, false
	for pos+12 <= len(data) {
		if ctx.Err() != nil {
			return 0
		}
		size := uint64(binary.BigEndian.Uint32(data[pos : pos+4]))
		if size > uint64(len(data)-pos-12) {
			return 0
		}
		end := pos + 12 + int(size)
		*budget -= int(size) + 12
		if *budget < 0 {
			return 0
		}
		kind := string(data[pos+4 : pos+8])
		for _, b := range data[pos+4 : pos+8] {
			if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z') {
				return 0
			}
		}
		if crc32.ChecksumIEEE(data[pos+4:end-4]) != binary.BigEndian.Uint32(data[end-4:end]) {
			return 0
		}
		if pos == 8 {
			if kind != "IHDR" || size != 13 {
				return 0
			}
			h := data[pos+8 : end-4]
			if binary.BigEndian.Uint32(h[:4]) == 0 || binary.BigEndian.Uint32(h[4:8]) == 0 || h[10] != 0 || h[11] != 0 || h[12] > 1 {
				return 0
			}
			depth, color := h[8], h[9]
			valid := color == 0 && (depth == 1 || depth == 2 || depth == 4 || depth == 8 || depth == 16) || color == 3 && (depth == 1 || depth == 2 || depth == 4 || depth == 8) || (color == 2 || color == 4 || color == 6) && (depth == 8 || depth == 16)
			if !valid {
				return 0
			}
		} else if kind == "IHDR" {
			return 0
		}
		if kind == "IDAT" {
			idat = true
		}
		if kind == "IEND" {
			if size == 0 && idat {
				return end
			}
			return 0
		}
		pos = end
	}
	return 0
}

func foremostGIF(ctx context.Context, data []byte, budget *int) int {
	if len(data) < 13 || binary.LittleEndian.Uint16(data[6:8]) == 0 || binary.LittleEndian.Uint16(data[8:10]) == 0 {
		return 0
	}
	pos := 13
	if data[10]&128 != 0 {
		pos += 3 * (1 << ((data[10] & 7) + 1))
	}
	images := 0
	for pos < len(data) {
		if ctx.Err() != nil {
			return 0
		}
		*budget -= 1
		if *budget < 0 {
			return 0
		}
		marker := data[pos]
		pos++
		switch marker {
		case 0x3b:
			if images > 0 {
				return pos
			}
			return 0
		case 0x21:
			if pos >= len(data) {
				return 0
			}
			pos++ // extension label
		case 0x2c:
			if pos+9 > len(data) {
				return 0
			}
			if binary.LittleEndian.Uint16(data[pos+4:pos+6]) == 0 || binary.LittleEndian.Uint16(data[pos+6:pos+8]) == 0 {
				return 0
			}
			packed := data[pos+8]
			pos += 9
			if packed&128 != 0 {
				pos += 3 * (1 << ((packed & 7) + 1))
			}
			if pos >= len(data) || data[pos] < 2 || data[pos] > 8 {
				return 0
			}
			pos++
			images++
		default:
			return 0
		}
		blocks := 0
		for {
			if pos >= len(data) {
				return 0
			}
			size := int(data[pos])
			pos++
			if size == 0 {
				break
			}
			if size > len(data)-pos {
				return 0
			}
			pos += size
			blocks++
			*budget -= size + 1
			if *budget < 0 || ctx.Err() != nil {
				return 0
			}
		}
		if marker == 0x2c && blocks == 0 {
			return 0
		}
	}
	return 0
}

func foremostBMP(data []byte) int {
	if len(data) < 54 {
		return 0
	}
	size := uint64(binary.LittleEndian.Uint32(data[2:6]))
	offset := uint64(binary.LittleEndian.Uint32(data[10:14]))
	dib := uint64(binary.LittleEndian.Uint32(data[14:18]))
	if size > uint64(len(data)) || size < 54 || !(dib == 40 || dib == 108 || dib == 124) || 14+dib > offset || offset >= size || binary.LittleEndian.Uint32(data[6:10]) != 0 {
		return 0
	}
	width := int32(binary.LittleEndian.Uint32(data[18:22]))
	height := int32(binary.LittleEndian.Uint32(data[22:26]))
	bits := uint64(binary.LittleEndian.Uint16(data[28:30]))
	if width <= 0 || height == 0 || binary.LittleEndian.Uint16(data[26:28]) != 1 || binary.LittleEndian.Uint32(data[30:34]) != 0 || !(bits == 1 || bits == 4 || bits == 8 || bits == 24 || bits == 32) {
		return 0
	}
	rows := int64(height)
	if rows < 0 {
		rows = -rows
	}
	payload := ((uint64(width)*bits + 31) / 32) * 4 * uint64(rows)
	if payload > size-offset {
		return 0
	}
	declaredPixels := uint64(binary.LittleEndian.Uint32(data[34:38]))
	if declaredPixels != 0 && declaredPixels != payload {
		return 0
	}
	if bits <= 8 {
		colors := uint64(binary.LittleEndian.Uint32(data[46:50]))
		if colors == 0 {
			colors = 1 << bits
		}
		if colors > 1<<bits || 14+dib+colors*4 > offset {
			return 0
		}
	}
	return int(size)
}

func foremostWAV(ctx context.Context, data []byte, budget *int) int {
	end64 := uint64(binary.LittleEndian.Uint32(data[4:8])) + 8
	if end64 > uint64(len(data)) || end64 < 12 {
		return 0
	}
	end, pos := int(end64), 12
	format, payload := false, false
	blockAlign := uint64(0)
	for pos+8 <= end {
		if ctx.Err() != nil {
			return 0
		}
		*budget -= 8
		if *budget < 0 {
			return 0
		}
		size := uint64(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
		kind := string(data[pos : pos+4])
		pos += 8
		if size > uint64(end-pos) {
			return 0
		}
		if kind == "fmt " {
			if format || size < 16 {
				return 0
			}
			h := data[pos : pos+16]
			channels := uint32(binary.LittleEndian.Uint16(h[2:4]))
			rate := binary.LittleEndian.Uint32(h[4:8])
			bits := uint32(binary.LittleEndian.Uint16(h[14:16]))
			align := uint32(binary.LittleEndian.Uint16(h[12:14]))
			if binary.LittleEndian.Uint16(h[:2]) != 1 || channels == 0 || rate == 0 || bits == 0 || bits%8 != 0 || align != channels*(bits/8) || uint64(rate)*uint64(align) != uint64(binary.LittleEndian.Uint32(h[8:12])) {
				return 0
			}
			format = true
			blockAlign = uint64(align)
		}
		if kind == "data" {
			if !format || size%blockAlign != 0 {
				return 0
			}
			payload = true
		}
		pos += int(size) + int(size%2)
	}
	if pos == end && format && payload {
		return end
	}
	return 0
}
