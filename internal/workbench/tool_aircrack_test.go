// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func airBeacon(privacy bool, rsn bool) []byte {
	b := make([]byte, 36)
	b[0] = 0x80
	copy(b[10:16], []byte{2, 3, 4, 5, 6, 7})
	copy(b[16:22], b[10:16])
	if privacy {
		b[34] = 0x10
	}
	b = append(b, 0, 4, 't', 'e', 's', 't')
	if rsn {
		b = append(b, 48, 18, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2)
	}
	return b
}
func airCapture(link uint32, frames ...[]byte) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint16(b[6:], 4)
	binary.LittleEndian.PutUint32(b[16:], 65535)
	binary.LittleEndian.PutUint32(b[20:], link)
	for _, f := range frames {
		h := make([]byte, 16)
		binary.LittleEndian.PutUint32(h[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(h[12:], uint32(len(f)))
		b = append(b, h...)
		b = append(b, f...)
	}
	return b
}
func runAir(data []byte) (*Report, error) {
	return auditAircrack(context.Background(), ToolRequest{Input: base64.StdEncoding.EncodeToString(data), Encoding: "base64"})
}
func TestAircrackWirelessProtection(t *testing.T) {
	for _, tc := range []struct {
		name         string
		privacy, rsn bool
		findings     int
		label        string
	}{
		{"open", false, false, 1, "Open"}, {"legacy", true, false, 1, "Legacy privacy"}, {"rsn", true, true, 0, "RSN advertised"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := runAir(airCapture(105, airBeacon(tc.privacy, tc.rsn)))
			if err != nil {
				t.Fatal(err)
			}
			if r.Limited || len(r.Findings) != tc.findings || len(r.Nodes) != 1 || !strings.Contains(r.Observations[0].Value, tc.label) {
				t.Fatalf("unexpected report %+v", r)
			}
		})
	}
}
func TestAircrackRadiotapFCSAndManagement(t *testing.T) {
	beacon := airBeacon(true, true)
	rt := []byte{0, 0, 9, 0, 2, 0, 0, 0, 0x10}
	packet := append(append(rt, beacon...), 0, 0, 0, 0)
	deauth := make([]byte, 26)
	deauth[0] = 0xc0
	copy(deauth[10:], []byte("secretCLIENT"))
	rt2 := []byte{0, 0, 8, 0, 0, 0, 0, 0}
	r, err := runAir(airCapture(127, packet, append(rt2, deauth...)))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Nodes) != 1 || !strings.Contains(r.Observations[len(r.Observations)-1].Value, "1 deauthentication") {
		t.Fatalf("unexpected report %+v", r)
	}
	for _, o := range r.Observations {
		if strings.Contains(o.Value, "secret") || strings.Contains(o.Target, "secret") {
			t.Fatal("retained client identity")
		}
	}
}
func TestAircrackTruncationAndMalformed(t *testing.T) {
	complete := airCapture(105, airBeacon(false, false))
	for n := 0; n < len(complete); n++ {
		if n == 24 {
			continue
		} // Empty capture is valid and has no AP evidence.
		if _, err := runAir(complete[:n]); err == nil {
			t.Fatalf("accepted truncated input length %d", n)
		}
	}
	for _, frame := range [][]byte{
		{0x80}, append([]byte{0x80}, make([]byte, 23)...), append(airBeacon(false, false), 48, 8, 1), append(airBeacon(false, false), 0, 0), append(airBeacon(false, false), 48, 0),
	} {
		r, err := runAir(airCapture(105, frame))
		if err != nil {
			t.Fatal(err)
		}
		if !r.Limited || len(r.Findings) != 0 || len(r.Nodes) != 0 {
			t.Fatalf("malformed beacon classified %+v", r)
		}
	}
	for _, rt := range [][]byte{{0, 0, 100, 0, 0, 0, 0, 0}, {0, 0, 8, 0, 0, 0, 0, 0x80}, {0, 0, 9, 0, 2, 0, 0, 0, 0x40}, {0, 0, 9, 0, 2, 0, 0, 0, 0x10}, {0, 0, 8, 0, 1, 0, 0, 0}} {
		r, err := runAir(airCapture(127, rt))
		if err != nil {
			t.Fatal(err)
		}
		if !r.Limited || len(r.Nodes) != 0 {
			t.Fatalf("malformed radiotap accepted %+v", r)
		}
	}
}
func TestAircrackPCAPBoundsAndCSV(t *testing.T) {
	csv := "BSSID,Privacy,ESSID\n02:03:04:05:06:07,OPN,test\n"
	r, err := auditAircrack(context.Background(), ToolRequest{Input: csv})
	if err != nil || len(r.Findings) != 1 {
		t.Fatalf("CSV regression %v %+v", err, r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditAircrack(ctx, ToolRequest{Input: csv}); err == nil {
		t.Fatal("ignored cancellation")
	}
	if _, err := auditAircrack(context.Background(), ToolRequest{RunEngine: true, Input: csv}); err == nil {
		t.Fatal("accepted engine")
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b[20:], 1) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 1) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[36:], 0) },
		func(b []byte) { b[4] = 3 },
	} {
		b := airCapture(105, airBeacon(false, false))
		mutate(b)
		if _, err := runAir(b); err == nil {
			t.Fatal("accepted invalid header")
		}
	}
}

func TestAircrackMalformedSecurityAndPacketTruncation(t *testing.T) {
	good := airBeacon(true, true)
	for n := 0; n < 18; n++ {
		b := airBeacon(true, false)
		b = append(b, 48, byte(n))
		b = append(b, good[len(good)-18:len(good)-18+n]...)
		r, err := runAir(airCapture(105, b))
		if err != nil || !r.Limited || len(r.Nodes) != 0 || len(r.Findings) != 0 {
			t.Fatalf("classified partial RSN %d: %v %+v", n, err, r)
		}
	}
	b := airCapture(105, airBeacon(false, false))
	binary.LittleEndian.PutUint32(b[36:], uint32(len(b)))
	r, err := runAir(b)
	if err != nil || !r.Limited || len(r.Findings) != 0 {
		t.Fatalf("truncated record classified %v %+v", err, r)
	}
}

func FuzzAircrackWirelessPCAP(f *testing.F) {
	f.Add(airCapture(105, airBeacon(true, true)))
	f.Add(airCapture(127, []byte{0, 0, 8, 0, 0, 0, 0, 0}))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxInput {
			t.Skip()
		}
		_, _ = auditWirelessPCAP(context.Background(), data)
	})
}
