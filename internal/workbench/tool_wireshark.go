// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
)

func auditWireshark(ctx context.Context, req ToolRequest) (*Report, error) {
	if req.RunEngine {
		return nil, fmt.Errorf("Wireshark engine and live capture execution are not implemented; supply an offline capture")
	}
	if req.Target != "" {
		return nil, fmt.Errorf("Wireshark analysis requires offline input, not a target")
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
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{10, 13, 13, 10}) {
		return inspectPCAPNG(ctx, data)
	}
	r, err := InspectCapture(data)
	if err != nil {
		return nil, err
	}
	// Existing classic-PCAP diagnostics also need to declare incomplete evidence.
	for _, gap := range r.Gaps {
		if strings.Contains(gap, "truncated packets") || strings.Contains(gap, "frames were omitted") {
			r.Limited = true
		}
	}
	return r, nil
}

type captureInterface struct {
	link uint16
	snap uint32
}

// inspectPCAPNG validates block structure before normalizing Ethernet EPBs to
// classic PCAP for the existing conversation analyzer. Timestamps and options
// are intentionally not used for timing or payload claims.
// Format reference: https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html
func inspectPCAPNG(ctx context.Context, data []byte) (*Report, error) {
	normalized := make([]byte, 24)
	binary.LittleEndian.PutUint32(normalized[:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(normalized[4:6], 2)
	binary.LittleEndian.PutUint16(normalized[6:8], 4)
	binary.LittleEndian.PutUint32(normalized[16:20], 0xffffffff)
	binary.LittleEndian.PutUint32(normalized[20:24], 1)
	var order binary.ByteOrder
	var interfaces []captureInterface
	sectionEnd := -1
	sections, packets, omitted := 0, 0, 0
	gaps := newReport("pcapng", "", nil)
	for offset := 0; offset < len(data); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(data)-offset < 12 {
			return nil, fmt.Errorf("truncated PCAPNG block at byte %d", offset)
		}
		block := data[offset:]
		section := binary.BigEndian.Uint32(block[:4]) == 0x0a0d0d0a
		if section {
			if sectionEnd >= 0 && offset != sectionEnd {
				return nil, fmt.Errorf("PCAPNG section length does not match next section")
			}
			switch binary.BigEndian.Uint32(block[8:12]) {
			case 0x1a2b3c4d:
				order = binary.BigEndian
			case 0x4d3c2b1a:
				order = binary.LittleEndian
			default:
				return nil, fmt.Errorf("invalid PCAPNG byte-order magic")
			}
		} else if order == nil {
			return nil, fmt.Errorf("PCAPNG must start with a section header")
		}
		size := uint64(order.Uint32(block[4:8]))
		if size < 12 || size%4 != 0 || size > uint64(len(block)) {
			return nil, fmt.Errorf("invalid PCAPNG block length at byte %d", offset)
		}
		block = block[:int(size)]
		if order.Uint32(block[len(block)-4:]) != uint32(size) {
			return nil, fmt.Errorf("PCAPNG trailing block length mismatch at byte %d", offset)
		}
		if !section && sectionEnd >= 0 && offset+len(block) > sectionEnd {
			return nil, fmt.Errorf("PCAPNG block exceeds declared section length")
		}
		body := block[8 : len(block)-4]
		switch order.Uint32(block[:4]) {
		case 0x0a0d0d0a:
			if len(body) < 16 || order.Uint16(body[4:6]) != 1 || order.Uint16(body[6:8]) != 0 {
				return nil, fmt.Errorf("unsupported or truncated PCAPNG section version (requires 1.0)")
			}
			if err := captureOptions(body[16:], order); err != nil {
				return nil, err
			}
			length := order.Uint64(body[8:16])
			sectionEnd = -1
			if length != ^uint64(0) {
				if length > uint64(len(data)-offset-len(block)) || length%4 != 0 {
					return nil, fmt.Errorf("invalid PCAPNG declared section length")
				}
				sectionEnd = offset + len(block) + int(length)
			}
			interfaces = nil // IDs are local to each section.
			sections++
		case 1:
			if len(body) < 8 || order.Uint16(body[2:4]) != 0 {
				return nil, fmt.Errorf("invalid PCAPNG interface description")
			}
			if err := captureOptions(body[8:], order); err != nil {
				return nil, err
			}
			iface := captureInterface{order.Uint16(body[:2]), order.Uint32(body[4:8])}
			interfaces = append(interfaces, iface)
			if iface.link != 1 {
				gaps.gap("Non-Ethernet interfaces are unsupported; their packets are omitted.")
				gaps.Limited = true
			}
		case 6:
			if len(body) < 20 {
				return nil, fmt.Errorf("truncated PCAPNG enhanced packet header")
			}
			id := uint64(order.Uint32(body[:4]))
			if id >= uint64(len(interfaces)) {
				return nil, fmt.Errorf("PCAPNG packet references an undefined interface")
			}
			iface := interfaces[int(id)]
			captured, original := uint64(order.Uint32(body[12:16])), uint64(order.Uint32(body[16:20]))
			padded := (captured + 3) &^ uint64(3)
			if captured > original || padded > uint64(len(body)-20) || iface.snap != 0 && captured > uint64(iface.snap) {
				return nil, fmt.Errorf("invalid PCAPNG captured packet length")
			}
			if err := captureOptions(body[20+int(padded):], order); err != nil {
				return nil, err
			}
			packets++
			if captured < original {
				gaps.Limited = true
				gaps.gap("The capture contains truncated packets.")
			}
			if iface.link != 1 || packets > 100000 || len(normalized)+16+int(captured) > MaxInput {
				omitted++
				gaps.Limited = true
				if iface.link == 1 {
					gaps.gap("Packet analysis reached its 100,000-packet or 8 MiB normalized-data limit.")
				}
				break
			}
			header := make([]byte, 16)
			binary.LittleEndian.PutUint32(header[8:12], uint32(captured))
			binary.LittleEndian.PutUint32(header[12:16], uint32(original))
			normalized = append(normalized, header...)
			normalized = append(normalized, body[20:20+int(captured)]...)
		default:
			gaps.Limited = true
			gaps.gap("Unsupported PCAPNG block types were skipped, including any simple/obsolete packet blocks and auxiliary metadata.")
		}
		offset += len(block)
	}
	if sectionEnd >= 0 && sectionEnd != len(data) {
		return nil, fmt.Errorf("PCAPNG section length does not match end of input")
	}
	r, err := InspectCapture(normalized)
	if err != nil {
		return nil, err
	}
	r.Tool, r.InputSHA256 = "pcapng", digest(data)
	r.Summary = fmt.Sprintf("Offline PCAPNG Ethernet conversations: %d sections, %d enhanced packets, %d omitted before frame analysis.", sections, packets, omitted)
	r.Limited = r.Limited || gaps.Limited
	for _, gap := range r.Gaps {
		if strings.Contains(gap, "frames were omitted") {
			r.Limited = true
		}
	}
	for _, gap := range gaps.Gaps {
		r.gap(gap)
	}
	r.gap("PCAPNG timestamps, interface statistics, names, comments and options are not interpreted. Simple/obsolete packet blocks are unsupported; enhanced packets on Ethernet interfaces are analyzed.")
	return r, nil
}

func captureOptions(data []byte, order binary.ByteOrder) error {
	for len(data) > 0 {
		if len(data) < 4 {
			return fmt.Errorf("truncated PCAPNG option header")
		}
		code, length := order.Uint16(data[:2]), int(order.Uint16(data[2:4]))
		data = data[4:]
		padded := (length + 3) &^ 3
		if padded > len(data) {
			return fmt.Errorf("PCAPNG option exceeds block length")
		}
		if code == 0 {
			if length != 0 || len(data) != 0 {
				return fmt.Errorf("invalid PCAPNG end-of-options marker")
			}
			return nil
		}
		data = data[padded:]
	}
	return nil
}
