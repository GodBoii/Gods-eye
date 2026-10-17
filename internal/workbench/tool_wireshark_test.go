// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func captureNGBlock(order binary.ByteOrder, kind uint32, body []byte) []byte {
	b := make([]byte, len(body)+12)
	order.PutUint32(b[:4], kind)
	order.PutUint32(b[4:8], uint32(len(b)))
	copy(b[8:], body)
	order.PutUint32(b[len(b)-4:], uint32(len(b)))
	return b
}

func captureNGSection(order binary.ByteOrder) []byte {
	b := make([]byte, 16)
	order.PutUint32(b[:4], 0x1a2b3c4d)
	order.PutUint16(b[4:6], 1)
	order.PutUint64(b[8:16], ^uint64(0))
	return captureNGBlock(order, 0x0a0d0d0a, b)
}

func captureNGInterface(order binary.ByteOrder, link uint16, snap uint32) []byte {
	b := make([]byte, 8)
	order.PutUint16(b[:2], link)
	order.PutUint32(b[4:8], snap)
	return captureNGBlock(order, 1, b)
}

func captureNGPacket(order binary.ByteOrder, id uint32, frame []byte, original uint32) []byte {
	b := make([]byte, 20+(len(frame)+3)&^3)
	order.PutUint32(b[:4], id)
	order.PutUint32(b[12:16], uint32(len(frame)))
	order.PutUint32(b[16:20], original)
	copy(b[20:], frame)
	return captureNGBlock(order, 6, b)
}

func captureNGFrame() []byte {
	frame := make([]byte, 54)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	frame[14], frame[23] = 0x45, 6
	binary.BigEndian.PutUint16(frame[16:18], 40)
	copy(frame[26:30], []byte{192, 0, 2, 1})
	copy(frame[30:34], []byte{192, 0, 2, 2})
	binary.BigEndian.PutUint16(frame[34:36], 1234)
	binary.BigEndian.PutUint16(frame[36:38], 443)
	return frame
}

func captureNGFixture(order binary.ByteOrder) []byte {
	data := captureNGSection(order)
	data = append(data, captureNGInterface(order, 1, 65535)...)
	frame := captureNGFrame()
	return append(data, captureNGPacket(order, 0, frame, uint32(len(frame)))...)
}

func TestWiresharkPCAPNGConversations(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		t.Run(order.String(), func(t *testing.T) {
			data := captureNGFixture(order)
			r, err := auditWireshark(context.Background(), ToolRequest{Input: base64.StdEncoding.EncodeToString(data), Encoding: "base64"})
			if err != nil {
				t.Fatal(err)
			}
			if r.Tool != "pcapng" || r.InputSHA256 != digest(data) || r.Limited || len(r.Edges) != 1 || len(r.Observations) != 2 || r.Observations[1].Kind != "TCP" || !strings.Contains(r.Observations[1].Target, "192.0.2.2:443") {
				t.Fatalf("incorrect conversations: %+v", r)
			}
		})
	}
	data := append(captureNGFixture(binary.LittleEndian), captureNGFixture(binary.BigEndian)...)
	r, err := auditWireshark(context.Background(), ToolRequest{Input: string(data)})
	if err != nil || !strings.Contains(r.Summary, "2 sections") || r.Observations[1].Value != "2 packets" {
		t.Fatal(r, err)
	}
}

func TestWiresharkPCAPNGRejectsMalformedStructure(t *testing.T) {
	valid := captureNGFixture(binary.LittleEndian)
	tests := []struct {
		name string
		edit func([]byte) []byte
	}{
		{"truncated header", func(b []byte) []byte { return b[:10] }},
		{"truncated packet", func(b []byte) []byte { return b[:len(b)-1] }},
		{"bad magic", func(b []byte) []byte { b[8] = 0; return b }},
		{"bad version", func(b []byte) []byte { b[12] = 2; return b }},
		{"unaligned block", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:8], 27); return b }},
		{"oversized block", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:8], 0xffffffff); return b }},
		{"trailer mismatch", func(b []byte) []byte { b[24] = 0; return b }},
		{"unknown interface", func(b []byte) []byte { b[56] = 1; return b }},
		{"capture exceeds original", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[72:76], 1); return b }},
		{"capture exceeds block", func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[68:72], 65535)
			binary.LittleEndian.PutUint32(b[72:76], 65535)
			return b
		}},
		{"capture exceeds snap", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[40:44], 8); return b }},
		{"reserved interface bits", func(b []byte) []byte { b[38] = 1; return b }},
		{"section length too large", func(b []byte) []byte { binary.LittleEndian.PutUint64(b[16:24], uint64(len(b))); return b }},
		{"section boundary inside block", func(b []byte) []byte { binary.LittleEndian.PutUint64(b[16:24], 4); return b }},
		{"interface reset", func(b []byte) []byte {
			return append(append(b, captureNGSection(binary.BigEndian)...), captureNGPacket(binary.BigEndian, 0, captureNGFrame(), 54)...)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := test.edit(bytes.Clone(valid))
			if _, err := auditWireshark(context.Background(), ToolRequest{Input: string(data)}); err == nil {
				t.Fatal("malformed capture accepted")
			}
		})
	}
	// A known section length excludes the section header itself.
	data := bytes.Clone(valid)
	binary.LittleEndian.PutUint64(data[16:24], uint64(len(data)-28))
	if _, err := auditWireshark(context.Background(), ToolRequest{Input: string(data)}); err != nil {
		t.Fatal(err)
	}
}

func TestWiresharkPCAPNGLimitedEvidence(t *testing.T) {
	order := binary.LittleEndian
	frame := captureNGFrame()
	tests := []struct {
		name string
		data []byte
	}{
		{"truncated frame", append(append(captureNGSection(order), captureNGInterface(order, 1, 65535)...), captureNGPacket(order, 0, frame[:38], 54)...)},
		{"unsupported interface", append(append(captureNGSection(order), captureNGInterface(order, 101, 0)...), captureNGPacket(order, 0, frame, 54)...)},
		{"unknown block", append(captureNGFixture(order), captureNGBlock(order, 0x9999, nil)...)},
		{"malformed Ethernet", append(append(captureNGSection(order), captureNGInterface(order, 1, 0)...), captureNGPacket(order, 0, []byte{1, 2, 3}, 3)...)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, err := auditWireshark(context.Background(), ToolRequest{Input: string(test.data)})
			if err != nil || !r.Limited || len(r.Gaps) < 2 {
				t.Fatal(r, err)
			}
		})
	}
}

func TestWiresharkOptionsAndRequests(t *testing.T) {
	for _, data := range [][]byte{
		{1, 0, 4, 0},             // declared value absent
		{0, 0, 1, 0, 0, 0, 0, 0}, // nonzero terminator length
		{0, 0, 0, 0, 1, 0, 0, 0}, // option after terminator
		{1, 0},
	} {
		if err := captureOptions(data, binary.LittleEndian); err == nil {
			t.Fatalf("bad options accepted: %v", data)
		}
	}
	options := []byte{1, 0, 1, 0, 'x', 0, 0, 0, 0, 0, 0, 0}
	if err := captureOptions(options, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
	// Exercise option validation through the capture parser as well.
	iface := make([]byte, 8)
	binary.LittleEndian.PutUint16(iface[:2], 1)
	for _, optionData := range [][]byte{options, {1, 0, 8, 0}} {
		data := append(captureNGSection(binary.LittleEndian), captureNGBlock(binary.LittleEndian, 1, append(bytes.Clone(iface), optionData...))...)
		_, err := auditWireshark(context.Background(), ToolRequest{Input: string(data)})
		if (err == nil) != bytes.Equal(optionData, options) {
			t.Fatal("option boundary validation failed", err)
		}
	}
	for _, req := range []ToolRequest{{}, {RunEngine: true}, {Target: "example.test"}, {Input: "x", Encoding: "unknown"}, {Input: "?", Encoding: "base64"}} {
		if _, err := auditWireshark(context.Background(), req); err == nil {
			t.Fatal("bad request accepted", req)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditWireshark(ctx, ToolRequest{Input: string(captureNGFixture(binary.LittleEndian))}); err != context.Canceled {
		t.Fatal("cancellation ignored", err)
	}
}

func TestWiresharkClassicPCAPRegression(t *testing.T) {
	data := make([]byte, 40)
	binary.LittleEndian.PutUint32(data[:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(data[4:6], 2)
	binary.LittleEndian.PutUint16(data[6:8], 4)
	binary.LittleEndian.PutUint32(data[20:24], 1)
	binary.LittleEndian.PutUint32(data[32:36], 54)
	binary.LittleEndian.PutUint32(data[36:40], 54)
	data = append(data, captureNGFrame()...)
	r, err := auditWireshark(context.Background(), ToolRequest{Input: string(data)})
	if err != nil || len(r.Edges) != 1 || r.Limited || r.InputSHA256 != digest(data) {
		t.Fatal(r, err)
	}
	binary.LittleEndian.PutUint32(data[36:40], 60)
	r, err = auditWireshark(context.Background(), ToolRequest{Input: string(data)})
	if err != nil || !r.Limited {
		t.Fatal("classic truncated evidence not marked limited", r, err)
	}
}

func FuzzWiresharkCaptureInput(f *testing.F) {
	f.Add(captureNGFixture(binary.LittleEndian))
	f.Add(captureNGFixture(binary.BigEndian))
	f.Add([]byte{10, 13, 13, 10})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxInput {
			t.Skip()
		}
		_, _ = auditWireshark(context.Background(), ToolRequest{Input: string(data)})
	})
}
