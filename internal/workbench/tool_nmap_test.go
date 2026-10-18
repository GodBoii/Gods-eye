// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"net"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNmapNativeRealBanner(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			done <- err
			return
		}
		_, err = conn.Write([]byte("SSH-2.0-local-test\r\n"))
		done <- err
	}()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	r, err := auditNmap(context.Background(), ToolRequest{Target: "127.0.0.1", Ports: []int{port}, Authorized: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	open, banner, native := false, false, false
	for _, observation := range r.Observations {
		open = open || observation.Kind == "TCP port" && observation.Value == "open"
		banner = banner || observation.Kind == "server banner" && strings.Contains(observation.Value, "SSH-2.0-local-test")
		native = native || observation.Kind == "execution" && strings.Contains(observation.Value, "not invoked")
	}
	if !open || !banner || !native || r.Limited || len(r.Findings) != 0 {
		t.Fatalf("unexpected report: %+v", r)
	}
}

func TestNmapRequestBoundaries(t *testing.T) {
	for _, req := range []ToolRequest{
		{Target: "127.0.0.1", Ports: []int{80}},
		{Target: "https://example.test", Ports: []int{80}, Authorized: true},
		{Target: "127.0.0.1/24", Ports: []int{80}, Authorized: true},
		{Target: "-oX", Ports: []int{80}, Authorized: true},
		{Target: "169.254.169.254", Ports: []int{80}, Authorized: true},
		{Target: "0.0.0.0", Ports: []int{80}, Authorized: true},
		{Target: "127.0.0.1", Authorized: true},
		{Target: "127.0.0.1", Ports: []int{80, 80}, Authorized: true},
		{Target: "127.0.0.1", Ports: []int{65536}, Authorized: true},
		{Target: "127.0.0.1", Ports: []int{80}, Authorized: true, Input: "ignored evidence"},
	} {
		if _, err := auditNmap(context.Background(), req); err == nil {
			t.Fatalf("accepted invalid request: %+v", req)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditNmap(ctx, ToolRequest{Target: "127.0.0.1", Ports: []int{80}, Authorized: true}); err == nil {
		t.Fatal("accepted cancelled assessment")
	}
}

func TestNmapEngineArgumentsPinnedAndBounded(t *testing.T) {
	ports := []int{443, 80}
	args, err := nmapArguments(netip.MustParseAddr("2001:db8::1"), ports)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"-sT", "-sV", "--version-light", "-Pn", "-n", "--max-retries", "1", "--host-timeout", "15s", "--max-parallelism", "4", "-p", "80,443", "-oX", "-", "-6", "2001:db8::1"}
	if !reflect.DeepEqual(args, expected) {
		t.Fatalf("unexpected engine command: %q", args)
	}
	if ports[0] != 443 {
		t.Fatal("mutated caller ports")
	}
	if _, err := nmapArguments(netip.MustParseAddr("127.0.0.1"), make([]int, 33)); err == nil {
		t.Fatal("accepted excessive ports")
	}
}

func TestNmapTLSRealUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	detail, issue := nmapTLS(ctx, conn, "127.0.0.1")
	if !strings.Contains(detail, "TLS 1.") || !strings.Contains(detail, "certificate expires") || issue == "" {
		t.Fatalf("detail=%q issue=%q", detail, issue)
	}
}
