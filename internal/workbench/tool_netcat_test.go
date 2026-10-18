// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNetcatProtocolExchanges(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		port                    int
		request, response, want string
		invalid                 bool
	}{
		{"http", 80, "HEAD / HTTP/1.1\r\nHost: localhost:80\r\nConnection: close\r\n\r\n", "HTTP/1.1 200 SECRET\r\nSet-Cookie: SECRET\r\n", "status 200", false},
		{"redis", 6379, "*1\r\n$4\r\nPING\r\n", "+PONG\r\n", "proves PING access only", false},
		{"redis auth", 6379, "*1\r\n$4\r\nPING\r\n", "-NOAUTH SECRET\r\n", "authentication required", false},
		{"memcached", 11211, "version\r\n", "VERSION SECRET\r\n", "version response confirmed", false},
		{"banner", 12345, "", "SSH-2.0-SECRET\r\n", "banner claim only", false},
		{"unrecognized", 80, "HEAD / HTTP/1.1\r\nHost: localhost:80\r\nConnection: close\r\n\r\n", "SECRET\r\n", "contents withheld", true},
		{"oversized", 6379, "*1\r\n$4\r\nPING\r\n", strings.Repeat("x", 5000) + "\n", "incomplete", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
				if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					done <- err
					return
				}
				data := make([]byte, len(tc.request))
				if _, err := io.ReadFull(conn, data); err != nil {
					done <- err
					return
				}
				if string(data) != tc.request {
					done <- io.ErrUnexpectedEOF
					return
				}
				_, err = io.WriteString(conn, tc.response)
				done <- err
			}()
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			result, err := netcatExchange(context.Background(), conn, "localhost", tc.port)
			conn.Close()
			if (err != nil) != tc.invalid || !strings.Contains(result, tc.want) || strings.Contains(result, "SECRET") {
				t.Fatalf("result=%q err=%v", result, err)
			}
			if serverErr := <-done; serverErr != nil && !tc.invalid {
				t.Fatal(serverErr)
			}
		})
	}
}

func TestNetcatSMTPAndCancellation(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		server.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(server)
		if _, err := io.WriteString(server, "220-test SECRET\r\n220 ready\r\n"); err != nil {
			done <- err
			return
		}
		line, err := reader.ReadString('\n')
		if err != nil || line != "EHLO godseye.invalid\r\n" {
			done <- io.ErrUnexpectedEOF
			return
		}
		if _, err := io.WriteString(server, "250-test SECRET\r\n250 OK\r\n"); err != nil {
			done <- err
			return
		}
		line, err = reader.ReadString('\n')
		if err != nil || line != "QUIT\r\n" {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, err = io.WriteString(server, "221 bye\r\n")
		done <- err
	}()
	result, err := netcatExchange(context.Background(), client, "localhost", 587)
	if err != nil || !strings.Contains(result, "EHLO and QUIT confirmed") || strings.Contains(result, "SECRET") {
		t.Fatalf("%q %v", result, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	server2, client2 := net.Pipe()
	defer server2.Close()
	defer client2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(30*time.Millisecond, cancel)
	defer timer.Stop()
	defer cancel()
	start := time.Now()
	if _, err := netcatExchange(ctx, client2, "localhost", 12345); err == nil || time.Since(start) > time.Second {
		t.Fatalf("blocked cancellation: %v", err)
	}
}

func TestNetcatValidation(t *testing.T) {
	for _, req := range []ToolRequest{
		{Target: "127.0.0.1", Ports: []int{80}},
		{Authorized: true, RunEngine: true, Target: "127.0.0.1", Ports: []int{80}},
		{Authorized: true, Target: "127.0.0.1", Ports: []int{80}, Input: "payload"},
		{Authorized: true, Target: "127.0.0.1", Ports: []int{80}, Encoding: "text"},
		{Authorized: true, Target: "example.com\r\nInjected: x", Ports: []int{80}},
		{Authorized: true, Target: "https://example.com", Ports: []int{80}},
		{Authorized: true, Target: "169.254.169.254", Ports: []int{80}},
		{Authorized: true, Target: "100.100.100.200", Ports: []int{80}},
		{Authorized: true, Target: "0.0.0.0", Ports: []int{80}},
		{Authorized: true, Target: "127.0.0.1"},
		{Authorized: true, Target: "127.0.0.1", Ports: []int{80, 80}},
		{Authorized: true, Target: "127.0.0.1", Ports: []int{0}},
		{Authorized: true, Target: "127.0.0.1", Ports: []int{65536}},
		{Authorized: true, Target: "127.0.0.1", Ports: []int{1, 2, 3, 4, 5, 6, 7, 8, 9}},
	} {
		if _, err := auditNetcat(context.Background(), req); err == nil {
			t.Fatalf("accepted invalid request: %+v", req)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditNetcat(ctx, ToolRequest{}); err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestNetcatLiveReportRedaction(t *testing.T) {
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
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = io.WriteString(conn, "SECRET service banner\r\n")
		done <- err
	}()
	r, err := auditNetcat(context.Background(), ToolRequest{Authorized: true, Target: "127.0.0.1", Ports: []int{listener.Addr().(*net.TCPAddr).Port}})
	if err != nil {
		t.Fatal(err)
	}
	if serverErr := <-done; serverErr != nil {
		t.Fatal(serverErr)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "SECRET") || len(r.Findings) > 0 || r.Limited {
		t.Fatalf("unexpected report: %s", encoded)
	}
}
