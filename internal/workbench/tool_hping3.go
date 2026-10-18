// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"syscall"
	"time"
)

const hping3Samples = 3

// auditHping3 measures TCP connection establishment, not packet-level RTT.
func auditHping3(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !req.Authorized {
		return nil, fmt.Errorf("confirm authorization before active network assessment")
	}
	if req.RunEngine {
		return nil, fmt.Errorf("hping3 raw-packet engine execution is not supported; use native TCP measurements")
	}
	if req.Input != "" || req.Encoding != "" {
		return nil, fmt.Errorf("TCP measurements accept a target and explicit ports, not input data")
	}
	if !validHost(req.Target) {
		return nil, fmt.Errorf("provide one hostname or IP address, without a URL or CIDR")
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
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
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
	r := newReport("hping3", "Three native TCP connection samples per explicit endpoint, with success ratios and connection latency statistics.", nil)
	r.observe("execution", req.Target, "Native Go TCP diagnostics; hping3 engine was not invoked")
	r.observe("pinned address", req.Target, address)
	r.observe("measurement budget", req.Target, "3 samples per endpoint; at most 8 ports and 24 connections; 700 ms per connection; 20 second total deadline")
	root := r.node("host", req.Target)
	r.edge(root, r.node("ip", address), "resolved to")
	if len(addresses) > 1 {
		r.Limited = true
		r.gap("Only the first sorted resolved address was measured; other DNS addresses were omitted.")
	}
	for _, port := range ports {
		target := net.JoinHostPort(address, strconv.Itoa(port))
		latencies := make([]time.Duration, 0, hping3Samples)
		counts := map[string]int{}
		attempted := 0
		for sample := 0; sample < hping3Samples && ctx.Err() == nil; sample++ {
			started := time.Now()
			conn, err := (&net.Dialer{Timeout: 700 * time.Millisecond}).DialContext(ctx, "tcp", target)
			elapsed := time.Since(started)
			attempted++
			state := hping3ConnectionState(err)
			counts[state]++
			if err == nil {
				latencies = append(latencies, elapsed)
				if closeErr := conn.Close(); closeErr != nil {
					r.Limited = true
					r.gap("A connected socket returned an error while closing.")
				}
			}
			r.observe("TCP sample", target, fmt.Sprintf("sample %d: %s; %.3f ms connection-attempt duration", sample+1, state, float64(elapsed.Microseconds())/1000))
		}
		r.observe("TCP connection success", target, fmt.Sprintf("%d/%d successful (%.1f%% of attempted); %d/3 samples attempted; refused=%d timeout=%d unknown=%d cancelled=%d", len(latencies), attempted, hping3SuccessPercent(len(latencies), attempted), attempted, counts["refused"], counts["timeout; state unknown"], counts["unknown network error"], counts["cancelled; state unknown"]))
		if len(latencies) > 0 {
			sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
			median := latencies[len(latencies)/2]
			if len(latencies)%2 == 0 {
				median = (latencies[len(latencies)/2-1] + median) / 2
			}
			r.observe("TCP connection latency", target, fmt.Sprintf("successful samples only: min=%.3f ms median=%.3f ms max=%.3f ms", float64(latencies[0].Microseconds())/1000, float64(median.Microseconds())/1000, float64(latencies[len(latencies)-1].Microseconds())/1000))
			r.edge(root, r.node("service", target), "accepted TCP during sampling")
		} else {
			r.observe("TCP connection latency", target, "No successful sample; latency statistics unavailable")
		}
		if len(latencies) > 0 && len(latencies) < attempted {
			r.observe("TCP stability", target, "Mixed success and failure in this short sample; investigate service availability and network conditions")
		}
		if counts["timeout; state unknown"]+counts["unknown network error"]+counts["cancelled; state unknown"] > 0 {
			r.Limited = true
			r.gap("Some connection attempts have unknown endpoint state; timeouts and network errors do not establish a closed port or packet loss.")
		}
		if ctx.Err() != nil {
			r.Limited = true
			r.gap("Measurement was cancelled or reached its deadline; remaining samples and endpoints were not measured.")
			break
		}
	}
	r.gap("A short connection-establishment snapshot, not packet RTT, packet-loss measurement, long-term availability, or vulnerability verification. No application payloads, ICMP, UDP, raw packets, flooding, spoofing, or firewall evasion.")
	return r, nil
}

func hping3ConnectionState(err error) string {
	if err == nil {
		return "connected"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled; state unknown"
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.Errno(10061)) {
		return "refused"
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() {
		return "timeout; state unknown"
	}
	return "unknown network error"
}

func hping3SuccessPercent(success, attempted int) float64 {
	if attempted == 0 {
		return 0
	}
	return float64(success) * 100 / float64(attempted)
}
