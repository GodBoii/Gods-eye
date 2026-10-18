// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
)

func TestHping3LiveConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan int, 1)
	go func() {
		count := 0
		for {
			conn, err := listener.Accept()
			if err != nil {
				accepted <- count
				return
			}
			count++
			conn.Close()
		}
	}()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedPort := closed.Addr().(*net.TCPAddr).Port
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := auditHping3(context.Background(), ToolRequest{Authorized: true, Target: "127.0.0.1", Ports: []int{listener.Addr().(*net.TCPAddr).Port, refusedPort}})
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
	if got := <-accepted; got != 3 {
		t.Fatalf("connection budget: got %d, want 3", got)
	}
	if r.Limited || len(r.Findings) != 0 {
		t.Fatalf("unexpected limited/vulnerability result: %+v", r)
	}
	var successes, refusals, latency bool
	for _, observation := range r.Observations {
		if observation.Kind == "TCP connection success" {
			successes = successes || strings.Contains(observation.Value, "3/3 successful (100.0%")
			refusals = refusals || strings.Contains(observation.Value, "0/3 successful (0.0%") && strings.Contains(observation.Value, "refused=3")
		}
		latency = latency || observation.Kind == "TCP connection latency" && strings.Contains(observation.Value, "min=") && strings.Contains(observation.Value, "median=") && strings.Contains(observation.Value, "max=")
	}
	if !successes || !refusals || !latency {
		t.Fatalf("missing observations: %+v", r.Observations)
	}
}

func TestHping3BoundaryValidation(t *testing.T) {
	tests := []struct {
		name string
		req  ToolRequest
	}{
		{"unauthorized", ToolRequest{Target: "127.0.0.1", Ports: []int{80}}},
		{"engine", ToolRequest{Authorized: true, RunEngine: true, Target: "127.0.0.1", Ports: []int{80}}},
		{"input", ToolRequest{Authorized: true, Input: "data", Target: "127.0.0.1", Ports: []int{80}}},
		{"encoding", ToolRequest{Authorized: true, Encoding: "text", Target: "127.0.0.1", Ports: []int{80}}},
		{"url", ToolRequest{Authorized: true, Target: "https://example.com", Ports: []int{80}}},
		{"metadata", ToolRequest{Authorized: true, Target: "169.254.169.254", Ports: []int{80}}},
		{"no ports", ToolRequest{Authorized: true, Target: "127.0.0.1"}},
		{"over cap", ToolRequest{Authorized: true, Target: "127.0.0.1", Ports: []int{1, 2, 3, 4, 5, 6, 7, 8, 9}}},
		{"duplicate", ToolRequest{Authorized: true, Target: "127.0.0.1", Ports: []int{80, 80}}},
		{"zero", ToolRequest{Authorized: true, Target: "127.0.0.1", Ports: []int{0}}},
		{"out of range", ToolRequest{Authorized: true, Target: "127.0.0.1", Ports: []int{65536}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := auditHping3(context.Background(), test.req); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditHping3(ctx, ToolRequest{Authorized: true, Target: "127.0.0.1", Ports: []int{80}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestHping3FailureClassification(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{nil, "connected"},
		{&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, "refused"},
		{&net.OpError{Op: "dial", Err: syscall.Errno(10061)}, "refused"},
		{context.DeadlineExceeded, "timeout; state unknown"},
		{context.Canceled, "cancelled; state unknown"},
		{errors.New("network unreachable"), "unknown network error"},
	} {
		if got := hping3ConnectionState(test.err); got != test.want {
			t.Errorf("%v: got %q, want %q", test.err, got, test.want)
		}
	}
}
