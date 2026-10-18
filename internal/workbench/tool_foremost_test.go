// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"image"
	"image/color"
	"image/gif"
	"image/png"
	"testing"
)

func foremostFixtures(t *testing.T) [][]byte {
	t.Helper()
	var p, g bytes.Buffer
	picture := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	picture.Set(0, 0, color.White)
	if err := png.Encode(&p, picture); err != nil {
		t.Fatal(err)
	}
	if err := gif.Encode(&g, picture, nil); err != nil {
		t.Fatal(err)
	}
	bmp := make([]byte, 58)
	copy(bmp, "BM")
	binary.LittleEndian.PutUint32(bmp[2:6], 58)
	binary.LittleEndian.PutUint32(bmp[10:14], 54)
	binary.LittleEndian.PutUint32(bmp[14:18], 40)
	binary.LittleEndian.PutUint32(bmp[18:22], 1)
	binary.LittleEndian.PutUint32(bmp[22:26], 1)
	binary.LittleEndian.PutUint16(bmp[26:28], 1)
	binary.LittleEndian.PutUint16(bmp[28:30], 24)
	wav := make([]byte, 46)
	copy(wav, "RIFF")
	binary.LittleEndian.PutUint32(wav[4:8], 38)
	copy(wav[8:12], "WAVE")
	copy(wav[12:16], "fmt ")
	binary.LittleEndian.PutUint32(wav[16:20], 16)
	binary.LittleEndian.PutUint16(wav[20:22], 1)
	binary.LittleEndian.PutUint16(wav[22:24], 1)
	binary.LittleEndian.PutUint32(wav[24:28], 8000)
	binary.LittleEndian.PutUint32(wav[28:32], 16000)
	binary.LittleEndian.PutUint16(wav[32:34], 2)
	binary.LittleEndian.PutUint16(wav[34:36], 16)
	copy(wav[36:40], "data")
	binary.LittleEndian.PutUint32(wav[40:44], 2)
	return [][]byte{p.Bytes(), g.Bytes(), bmp, wav}
}

func foremostRequest(data []byte) ToolRequest {
	return ToolRequest{Tool: "foremost", Input: base64.StdEncoding.EncodeToString(data), Encoding: "base64"}
}

func TestForemostEmbeddedRanges(t *testing.T) {
	fixtures := foremostFixtures(t)
	input := []byte("prefix")
	var offsets []int
	for _, f := range fixtures {
		offsets = append(offsets, len(input))
		input = append(input, f...)
		input = append(input, 0, 0, 0)
	}
	r, err := auditForemost(context.Background(), foremostRequest(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Artifacts) != 4 {
		t.Fatalf("got %d artifacts: %+v", len(r.Artifacts), r)
	}
	for i, a := range r.Artifacts {
		if a.Offset != offsets[i] || a.Length != len(fixtures[i]) || !bytes.Equal(input[a.Offset:a.Offset+a.Length], fixtures[i]) {
			t.Fatalf("wrong byte range %+v", a)
		}
	}
}

func TestForemostTruncationAndFalseMagic(t *testing.T) {
	for i, f := range foremostFixtures(t) {
		for _, data := range [][]byte{f[:len(f)-1], f[:12]} {
			r, err := auditForemost(context.Background(), foremostRequest(data))
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Artifacts) != 0 {
				t.Fatalf("fixture %d accepted truncation", i)
			}
		}
	}
	fake := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x00IEND\xaeB`\x82GIF89aBMRIFF0000WAVE")
	r, err := auditForemost(context.Background(), foremostRequest(fake))
	if err != nil || len(r.Artifacts) != 0 {
		t.Fatalf("false magic accepted: %+v %v", r, err)
	}
	p := bytes.Clone(foremostFixtures(t)[0])
	p[29] ^= 1
	r, err = auditForemost(context.Background(), foremostRequest(p))
	if err != nil || len(r.Artifacts) != 0 {
		t.Fatal("PNG CRC corruption accepted")
	}
}

func TestForemostBoundsCancellationAndMode(t *testing.T) {
	bmp := foremostFixtures(t)[2]
	for _, count := range []int{32, 33} {
		r, err := auditForemost(context.Background(), foremostRequest(bytes.Repeat(bmp, count)))
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Artifacts) != 32 || r.Limited != (count == 33) {
			t.Fatalf("cap count=%d report=%+v", count, r)
		}
	}
	r, err := auditForemost(context.Background(), foremostRequest(bytes.Repeat([]byte("BM"), 257)))
	if err != nil || !r.Limited {
		t.Fatalf("header budget not enforced: %+v %v", r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditForemost(ctx, foremostRequest(bmp)); err == nil {
		t.Fatal("cancel ignored")
	}
	for _, req := range []ToolRequest{{RunEngine: true}, {Target: "example.com"}, {Input: "!", Encoding: "base64"}, {Input: ""}, {Input: string(bytes.Repeat([]byte{'x'}, MaxInput+1))}} {
		if _, err := auditForemost(context.Background(), req); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
}
