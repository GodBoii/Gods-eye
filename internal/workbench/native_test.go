// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTCPRealListenerAndBoundaries(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	r, err := TCP(context.Background(), "127.0.0.1", []int{port})
	if err != nil || len(r.Observations) != 2 || !strings.Contains(r.Observations[1].Value, "open") {
		t.Fatal(r, err)
	}
	for _, host := range []string{"https://example.test", "127.0.0.1/24", "169.254.169.254", "0.0.0.0", "100.100.100.200", "-option"} {
		if _, err := TCP(context.Background(), host, []int{80}); err == nil {
			t.Errorf("accepted %s", host)
		}
	}
	for _, ports := range [][]int{{}, {0}, {65536}, {80, 80}} {
		if _, err := TCP(context.Background(), "127.0.0.1", ports); err == nil {
			t.Fatal("bad ports accepted")
		}
	}
	for _, addr := range []string{"::ffff:169.254.169.254", "ff02::1", "fe80::1"} {
		if diagnosticAddress(netip.MustParseAddr(addr)) {
			t.Fatal("unsupported address accepted", addr)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := TCP(ctx, "127.0.0.1", []int{port}); err == nil {
		t.Fatal("cancelled resolution accepted")
	}
}

func TestIAMPolicyReview(t *testing.T) {
	r, err := IAM([]byte(`{"Statement":{"Sid":"Fixture","Effect":"Allow","Action":["s3:*","iam:PassRole"],"Resource":"*","Principal":{"AWS":["*"]}}}`))
	if err != nil || len(r.Findings) != 4 {
		t.Fatal(r, err)
	}
	r, err = IAM([]byte(`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`))
	if err != nil || len(r.Findings) != 0 {
		t.Fatal(r, err)
	}
	for _, data := range []string{`{}`, `{"Statement":[]}`, `{"Statement":{"Effect":"Allow","Action":1}}`, `{"Statement":{"Effect":"invalid"}}`} {
		if _, err := IAM([]byte(data)); err == nil {
			t.Fatal("bad policy accepted", data)
		}
	}
}

func TestFileRecoveryAndPCAP(t *testing.T) {
	data := append([]byte("prefix"), []byte{0xff, 0xd8, 0xff, 0x01, 0xff, 0xd9}...)
	r, err := InspectFile(data)
	if err != nil || len(r.Artifacts) != 1 || r.Artifacts[0].Offset != 6 || r.Artifacts[0].Length != 6 {
		t.Fatal(r, err)
	}
	if !bytes.Equal(data[r.Artifacts[0].Offset:r.Artifacts[0].Offset+r.Artifacts[0].Length], []byte{0xff, 0xd8, 0xff, 0x01, 0xff, 0xd9}) {
		t.Fatal("wrong recovered slice")
	}
	frame := make([]byte, 14+20+20)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	frame[14] = 0x45
	frame[23] = 6
	binary.BigEndian.PutUint16(frame[16:18], 40)
	copy(frame[26:30], []byte{192, 0, 2, 1})
	copy(frame[30:34], []byte{192, 0, 2, 2})
	binary.BigEndian.PutUint16(frame[34:36], 1234)
	binary.BigEndian.PutUint16(frame[36:38], 443)
	capture := make([]byte, 24+16)
	binary.LittleEndian.PutUint32(capture[:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(capture[4:6], 2)
	binary.LittleEndian.PutUint16(capture[6:8], 4)
	binary.LittleEndian.PutUint32(capture[20:24], 1)
	binary.LittleEndian.PutUint32(capture[32:36], uint32(len(frame)))
	binary.LittleEndian.PutUint32(capture[36:40], uint32(len(frame)))
	capture = append(capture, frame...)
	r, err = InspectCapture(capture)
	if err != nil || len(r.Edges) != 1 || r.Observations[1].Kind != "TCP" || !strings.Contains(r.Observations[1].Target, "192.0.2.2:443") {
		t.Fatal(r, err)
	}
	if _, err := InspectCapture(capture[:len(capture)-1]); err == nil {
		t.Fatal("truncated capture accepted")
	}
	pcapng := make([]byte, 24)
	copy(pcapng, []byte{0x0a, 0x0d, 0x0d, 0x0a})
	if _, err := InspectCapture(pcapng); err == nil {
		t.Fatal("PCAPNG mislabeled as supported")
	}
}

func TestEvidencePersistsAndRetainsTwenty(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 22; i++ {
		r, err := InspectFile([]byte("fixture"))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(r); err != nil {
			t.Fatal(err)
		}
	}
	items := store.List()
	if len(items) != 20 {
		t.Fatal("retention failed")
	}
	restored, err := OpenStore(dir)
	if err != nil || len(restored.List()) != 20 || restored.Get(items[0].ID) == nil {
		t.Fatal("restart lost evidence", err)
	}
	if err := os.WriteFile(filepath.Join(dir, items[0].ID+".json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err == nil {
		t.Fatal("corrupt report ignored")
	}
}

func FuzzImportBoundaries(f *testing.F) {
	f.Add("nuclei", []byte(`{}`))
	f.Add("nmap", []byte(`<nmaprun/>`))
	f.Add("har", []byte(`{"log":{"version":"1.2","entries":[]}}`))
	f.Fuzz(func(t *testing.T, format string, data []byte) {
		if len(data) > MaxInput {
			return
		}
		_, _ = Import(format, data)
	})
}
