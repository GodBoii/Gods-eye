// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func auditNmap(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !req.Authorized {
		return nil, fmt.Errorf("confirm authorization before active network assessment")
	}
	if !validHost(req.Target) {
		return nil, fmt.Errorf("provide one hostname or IP address, without a URL or CIDR")
	}
	if _, err := nmapArguments(netip.MustParseAddr("127.0.0.1"), req.Ports); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", req.Target)
	if err != nil || len(addresses) == 0 {
		return nil, fmt.Errorf("could not resolve the target host")
	}
	unique := make([]netip.Addr, 0, len(addresses))
	seen := map[netip.Addr]bool{}
	for _, address := range addresses {
		address = address.Unmap()
		if !diagnosticAddress(address) {
			return nil, fmt.Errorf("target resolves to an unsupported special-purpose address")
		}
		if !seen[address] {
			unique = append(unique, address)
			seen[address] = true
		}
	}
	sort.Slice(unique, func(i, j int) bool { return unique[i].Less(unique[j]) })
	if req.RunEngine {
		args, err := nmapArguments(unique[0], req.Ports)
		if err != nil {
			return nil, err
		}
		data, err := runAuditEngine(ctx, "nmap", args)
		if err != nil {
			return nil, fmt.Errorf("Nmap engine: %w", err)
		}
		r := newReport("nmap", "Installed Nmap TCP connect and light service identification for one pinned address.", data)
		if err := importNmap(r, data); err != nil {
			return nil, fmt.Errorf("Nmap engine output: %w", err)
		}
		r.observe("execution", req.Target, "Installed nmap engine executed; TCP connect and light service probes only")
		r.observe("pinned address", req.Target, unique[0].String())
		if len(unique) > 1 {
			r.gap("Engine mode assessed only the first sorted resolved address; other addresses were not scanned.")
		}
		r.gap("No NSE, UDP scan, OS detection, exploit verification, or all-port assessment. Service versions are observations, not confirmed vulnerabilities.")
		// A host timeout can still produce a successful XML document with no host.
		var completion struct {
			XMLName  xml.Name   `xml:"nmaprun"`
			Hosts    []struct{} `xml:"host"`
			Finished struct {
				Exit string `xml:"exit,attr"`
			} `xml:"runstats>finished"`
		}
		if err := decodeXML(data, &completion); err != nil {
			return nil, err
		}
		if len(completion.Hosts) == 0 || completion.Finished.Exit != "success" {
			r.Limited = true
			r.gap("Nmap produced no host record or did not declare successful completion; review for a host timeout or incomplete run.")
		}
		return r, nil
	}
	return nmapNative(ctx, req, unique), nil
}

func nmapArguments(address netip.Addr, ports []int) ([]string, error) {
	if !diagnosticAddress(address) {
		return nil, fmt.Errorf("unsupported target address")
	}
	if len(ports) < 1 || len(ports) > 32 {
		return nil, fmt.Errorf("provide 1 to 32 explicit TCP ports")
	}
	ordered := append([]int(nil), ports...)
	sort.Ints(ordered)
	portText := make([]string, len(ordered))
	for i, port := range ordered {
		if port < 1 || port > 65535 || i > 0 && ordered[i-1] == port {
			return nil, fmt.Errorf("ports must be unique integers from 1 to 65535")
		}
		portText[i] = strconv.Itoa(port)
	}
	args := []string{"-sT", "-sV", "--version-light", "-Pn", "-n", "--max-retries", "1", "--host-timeout", "15s", "--max-parallelism", "4", "-p", strings.Join(portText, ","), "-oX", "-"}
	if address.Is6() {
		args = append(args, "-6")
	}
	return append(args, address.String()), nil
}

type nmapProbeResult struct {
	target    string
	state     string
	banner    string
	tlsDetail string
	tlsIssue  string
}

func nmapNative(ctx context.Context, req ToolRequest, addresses []netip.Addr) *Report {
	r := newReport("nmap", "Native multi-address TCP inventory with bounded banner and TLS observations.", nil)
	r.observe("execution", req.Target, "Native Go diagnostics executed; Nmap engine was not invoked")
	if len(addresses) > 4 {
		addresses = addresses[:4]
		r.Limited = true
		r.gap("Only the first four sorted resolved addresses were assessed.")
	}
	root := r.node("host", req.Target)
	type job struct {
		address netip.Addr
		port    int
	}
	jobs := make(chan job, len(addresses)*len(req.Ports))
	results := make(chan nmapProbeResult, cap(jobs))
	for _, address := range addresses {
		r.observe("resolved address", req.Target, address.String())
		r.edge(root, r.node("ip", address.String()), "resolved to")
		for _, port := range req.Ports {
			jobs <- job{address, port}
		}
	}
	close(jobs)
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					return
				}
				results <- nmapProbe(ctx, req.Target, item.address, item.port)
			}
		}()
	}
	workers.Wait()
	close(results)
	var ordered []nmapProbeResult
	for result := range results {
		ordered = append(ordered, result)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].target < ordered[j].target })
	for _, result := range ordered {
		r.observe("TCP port", result.target, result.state)
		if result.state != "open" && result.state != "closed; connection refused" {
			r.Limited = true
			r.gap("At least one TCP endpoint could not be classified because it was unreachable or timed out.")
		}
		if result.state == "open" {
			r.edge(root, r.node("service", result.target), "accepts TCP")
		}
		if result.banner != "" {
			r.observe("server banner", result.target, result.banner)
		}
		if result.tlsDetail != "" {
			r.observe("TLS", result.target, result.tlsDetail)
		}
		if result.tlsIssue != "" {
			r.finding("medium", "TLS certificate verification failed", result.target, result.tlsIssue)
		}
	}
	if ctx.Err() != nil || len(ordered) != len(addresses)*len(req.Ports) {
		r.Limited = true
		r.gap("Assessment was cancelled or reached its deadline; uncompleted ports have unknown state.")
	}
	r.gap("Native mode reads at most 512 server-first banner bytes and attempts TLS on known implicit TLS ports only. No protocol payloads, STARTTLS, service-version database, UDP, NSE, OS detection or exploit checks. Open ports and banners do not prove a vulnerability.")
	return r
}

func nmapProbe(ctx context.Context, host string, address netip.Addr, port int) nmapProbeResult {
	target := net.JoinHostPort(address.String(), strconv.Itoa(port))
	result := nmapProbeResult{target: target, state: "unreachable or refused; state unknown"}
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", target)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			result.state = "closed; connection refused"
		} else if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
			result.state = "timed out; state unknown"
		}
		return result
	}
	defer conn.Close()
	result.state = "open"
	deadline, _ := probeCtx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		result.banner = "Connection deadline could not be set"
		return result
	}
	switch port {
	case 443, 465, 636, 853, 993, 995, 8443:
		result.tlsDetail, result.tlsIssue = nmapTLS(probeCtx, conn, host)
	default:
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		if n > 0 {
			result.banner = text(string(buf[:n]))
		}
	}
	return result
}

func nmapTLS(ctx context.Context, conn net.Conn, host string) (string, string) {
	// Verification is performed explicitly below so invalid certificates remain observable.
	client := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := client.HandshakeContext(ctx); err != nil {
		return "TLS handshake failed; protocol and certificate status unknown", ""
	}
	state := client.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "TLS completed without a peer certificate", ""
	}
	leaf := state.PeerCertificates[0]
	detail := fmt.Sprintf("%s; %s; certificate expires %s", tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite), leaf.NotAfter.UTC().Format(time.RFC3339))
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: intermediates}); err != nil {
		return detail, "Certificate chain, hostname or validity failed verification: " + err.Error()
	}
	return detail + "; certificate verified", ""
}
