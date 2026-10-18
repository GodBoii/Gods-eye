// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// auditNetcat uses fixed read-only probes, never user-supplied socket payloads.
func auditNetcat(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !req.Authorized {
		return nil, fmt.Errorf("confirm authorization before active service assessment")
	}
	if req.RunEngine {
		return nil, fmt.Errorf("netcat engine execution is not supported")
	}
	if req.Input != "" || req.Encoding != "" || !validHost(req.Target) {
		return nil, fmt.Errorf("provide one hostname or IP and explicit ports; payload input is not accepted")
	}
	if len(req.Ports) < 1 || len(req.Ports) > 8 {
		return nil, fmt.Errorf("provide 1 to 8 explicit TCP ports")
	}
	ports := append([]int(nil), req.Ports...)
	sort.Ints(ports)
	for i, port := range ports {
		if port < 1 || port > 65535 || i > 0 && ports[i-1] == port {
			return nil, fmt.Errorf("ports must be unique integers from 1 to 65535")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", req.Target)
	if err != nil || len(addresses) == 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("could not resolve the target host")
	}
	for _, address := range addresses {
		if !diagnosticAddress(address) {
			return nil, fmt.Errorf("target resolves to an unsupported special-purpose address")
		}
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })
	address := addresses[0].Unmap().String()
	r := newReport("netcat", "Bounded native TCP service verification using fixed read-only protocol probes.", nil)
	r.observe("execution", req.Target, "Native Go sockets; no netcat executable invoked")
	r.observe("pinned address", req.Target, address)
	r.observe("probe budget", req.Target, "At most 8 connections; 700 ms dial, 1200 ms exchange, 4096 response bytes per endpoint; 15 second total deadline")
	root := r.node("host", req.Target)
	r.edge(root, r.node("ip", address), "resolved to")
	if len(addresses) > 1 {
		r.Limited = true
		r.gap("Only the first sorted DNS address was probed; other addresses were omitted.")
	}
	for _, port := range ports {
		if ctx.Err() != nil {
			r.Limited = true
			r.gap("Assessment cancelled or deadline reached; remaining ports were not assessed.")
			break
		}
		target := net.JoinHostPort(address, strconv.Itoa(port))
		conn, err := (&net.Dialer{Timeout: 700 * time.Millisecond}).DialContext(ctx, "tcp", target)
		if err != nil {
			r.Limited = true
			r.observe("TCP connection", target, "Connection failed; protocol state unknown")
			continue
		}
		r.edge(root, r.node("service", target), "accepted TCP")
		result, probeErr := netcatExchange(ctx, conn, req.Target, port)
		if closeErr := conn.Close(); closeErr != nil {
			r.Limited = true
			r.gap("A socket returned an error while closing.")
		}
		r.observe("service verification", target, result)
		if probeErr != nil {
			r.Limited = true
			r.observe("probe outcome", target, "Protocol exchange incomplete, timed out, cancelled, or invalid; no vulnerability conclusion")
		}
	}
	r.gap("Fixed HTTP HEAD / on 80/8080, SMTP EHLO/QUIT on 25/587, Redis PING on 6379, Memcached version on 11211; other ports receive server-first banner observation only. Response contents are withheld. No TLS negotiation, credentials, arbitrary payloads, exploit attempts, listeners, relays, shells, or database audit. A response is not proof of a vulnerability.")
	return r, nil
}

// The connection is owned by the caller; cancellation interrupts blocked I/O.
func netcatExchange(ctx context.Context, conn net.Conn, host string, port int) (string, error) {
	if !validHost(host) {
		return "Probe rejected", fmt.Errorf("invalid host")
	}
	if err := ctx.Err(); err != nil {
		return "Probe cancelled", err
	}
	if err := conn.SetDeadline(time.Now().Add(1200 * time.Millisecond)); err != nil {
		return "Could not set probe deadline", err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	reader := bufio.NewReaderSize(io.LimitReader(conn, 4096), 512)
	line := func() (string, error) {
		value, err := reader.ReadString('\n')
		return strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r"), err
	}
	write := func(value string) error { _, err := io.WriteString(conn, value); return err }
	switch port {
	case 80, 8080:
		if err := write("HEAD / HTTP/1.1\r\nHost: " + net.JoinHostPort(host, strconv.Itoa(port)) + "\r\nConnection: close\r\n\r\n"); err != nil {
			return "HTTP HEAD write failed", err
		}
		value, err := line()
		if err != nil {
			return "No complete HTTP status line", err
		}
		fields := strings.Fields(value)
		if len(fields) >= 2 && (fields[0] == "HTTP/1.0" || fields[0] == "HTTP/1.1") && len(fields[1]) == 3 {
			status, parseErr := strconv.Atoi(fields[1])
			if parseErr == nil && status >= 100 && status <= 599 {
				return fmt.Sprintf("HTTP response confirmed; HEAD / status %d", status), nil
			}
		}
		return "Unrecognized HTTP status line (contents withheld)", fmt.Errorf("invalid HTTP response")
	case 25, 587:
		readSMTP := func(code string) error {
			for count := 0; count < 32; count++ {
				value, err := line()
				if err != nil {
					return err
				}
				if strings.HasPrefix(value, code+" ") {
					return nil
				}
				if !strings.HasPrefix(value, code+"-") {
					return fmt.Errorf("unexpected SMTP reply")
				}
			}
			return fmt.Errorf("SMTP reply line budget exceeded")
		}
		if err := readSMTP("220"); err != nil {
			return "SMTP greeting unconfirmed", err
		}
		if err := write("EHLO godseye.invalid\r\n"); err != nil {
			return "SMTP greeting confirmed; EHLO write failed", err
		}
		if err := readSMTP("250"); err != nil {
			return "SMTP greeting confirmed; EHLO not confirmed", err
		}
		if err := write("QUIT\r\n"); err != nil {
			return "SMTP greeting and EHLO confirmed; QUIT write failed", err
		}
		if err := readSMTP("221"); err != nil {
			return "SMTP greeting and EHLO confirmed; QUIT response incomplete", err
		}
		return "SMTP greeting, EHLO and QUIT confirmed; no mail submission attempted", nil
	case 6379:
		if err := write("*1\r\n$4\r\nPING\r\n"); err != nil {
			return "Redis PING write failed", err
		}
		value, err := line()
		if err != nil {
			return "Redis response incomplete", err
		}
		if value == "+PONG" {
			return "Redis PING/PONG confirmed; proves PING access only, not unrestricted database access", nil
		}
		if strings.HasPrefix(value, "-NOAUTH ") {
			return "Redis rejected PING with NOAUTH; authentication required for this command", nil
		}
		return "Redis PONG not confirmed (response contents withheld)", fmt.Errorf("unrecognized Redis response")
	case 11211:
		if err := write("version\r\n"); err != nil {
			return "Memcached version request failed", err
		}
		value, err := line()
		if err != nil {
			return "Memcached response incomplete", err
		}
		if strings.HasPrefix(value, "VERSION ") && len(value) > len("VERSION ") {
			return "Memcached version response confirmed; version contents withheld; data access not tested", nil
		}
		return "Memcached version response not confirmed (contents withheld)", fmt.Errorf("unrecognized Memcached response")
	default:
		value, err := line()
		if err != nil {
			return "No complete server-first banner; service identity unknown", err
		}
		if strings.HasPrefix(value, "SSH-2.0-") || strings.HasPrefix(value, "SSH-1.99-") {
			return "SSH server-first banner observed; banner claim only; no handshake or authentication attempted", nil
		}
		return "Server-first response observed; contents withheld and protocol identity unverified", nil
	}
}
