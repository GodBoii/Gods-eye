// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func validHost(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, "/\\@?#%\x00\t\r\n ") || strings.HasPrefix(host, "-") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// A diagnostic can explicitly reach loopback or private machines. It cannot
// probe unspecified, multicast, link-local or cloud-metadata destinations.
func diagnosticAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && (ip.IsGlobalUnicast() || ip.IsLoopback()) && ip.String() != "255.255.255.255" && !netip.MustParsePrefix("100.100.100.0/24").Contains(ip)
}

func TCP(ctx context.Context, host string, ports []int) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validHost(host) {
		return nil, fmt.Errorf("provide one hostname or IP address, without a URL or CIDR")
	}
	if len(ports) < 1 || len(ports) > 32 {
		return nil, fmt.Errorf("provide 1 to 32 explicit TCP ports")
	}
	seen := map[int]bool{}
	for _, port := range ports {
		if port < 1 || port > 65535 || seen[port] {
			return nil, fmt.Errorf("ports must be unique integers from 1 to 65535")
		}
		seen[port] = true
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, fmt.Errorf("could not resolve the target host")
	}
	for _, address := range addresses {
		if !diagnosticAddress(address) {
			return nil, fmt.Errorf("target resolves to an unsupported special-purpose address")
		}
	}
	// Pin one resolved address. No second name resolution occurs during dialing.
	address := addresses[0].Unmap().String()
	r := newReport("tcp", "TCP connectivity for one host and explicitly selected ports.", nil)
	r.observe("resolved address", host, address)
	root := r.node("host", host)
	r.edge(root, r.node("ip", address), "resolved to")
	type result struct {
		port    int
		status  string
		elapsed time.Duration
	}
	jobs := make(chan int, len(ports))
	results := make(chan result, len(ports))
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for port := range jobs {
				if ctx.Err() != nil {
					return
				}
				started := time.Now()
				connection, err := (&net.Dialer{Timeout: 700 * time.Millisecond}).DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
				status := "unreachable or refused"
				if err == nil {
					status = "open"
					if err := connection.Close(); err != nil {
						status = "open; connection close failed"
					}
				} else if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
					status = "timed out; state unknown"
				}
				results <- result{port, status, time.Since(started)}
			}
		}()
	}
	for _, port := range ports {
		jobs <- port
	}
	close(jobs)
	workers.Wait()
	close(results)
	var ordered []result
	for item := range results {
		ordered = append(ordered, item)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].port < ordered[j].port })
	for _, item := range ordered {
		target := net.JoinHostPort(address, strconv.Itoa(item.port))
		r.observe("TCP port", target, fmt.Sprintf("%s · %.1f ms", item.status, float64(item.elapsed.Microseconds())/1000))
		if strings.HasPrefix(item.status, "open") {
			r.edge(root, r.node("service", target), "accepts TCP")
		}
	}
	if ctx.Err() != nil {
		r.Limited = true
		r.gap("The diagnostic was cancelled or reached its 10 second deadline.")
	}
	r.gap("Connect-only diagnostics. No service fingerprinting, payloads, raw packets, listeners, port ranges or subnet discovery. An open port is not a vulnerability.")
	return r, nil
}

func DNS(ctx context.Context, domain string) (*Report, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if !validHost(domain) || net.ParseIP(domain) != nil || !strings.Contains(domain, ".") {
		return nil, fmt.Errorf("provide one ASCII domain name, using punycode for international names")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	r := newReport("dns", "DNS infrastructure and mail-policy observations for one domain.", nil)
	root := r.node("domain", domain)
	resolver := net.DefaultResolver
	lookupError := func(kind string, err error) {
		if err == nil {
			return
		}
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			r.observe(kind, domain, "No record returned by the configured resolver")
		} else {
			r.Limited = true
			r.gap(kind + " lookup failed or timed out.")
		}
	}
	ips, err := resolver.LookupNetIP(ctx, "ip", domain)
	lookupError("A / AAAA", err)
	for _, ip := range ips {
		r.observe("A / AAAA", domain, ip.String())
		r.edge(root, r.node("ip", ip.String()), "resolves to")
	}
	names, err := resolver.LookupNS(ctx, domain)
	lookupError("NS", err)
	for _, ns := range names {
		r.observe("NS", domain, ns.Host)
		r.edge(root, r.node("domain", strings.TrimSuffix(ns.Host, ".")), "delegates to")
	}
	mail, err := resolver.LookupMX(ctx, domain)
	lookupError("MX", err)
	for _, mx := range mail {
		r.observe("MX", domain, fmt.Sprintf("%s · priority %d", mx.Host, mx.Pref))
		r.edge(root, r.node("domain", strings.TrimSuffix(mx.Host, ".")), "mail handled by")
	}
	txt, txtErr := resolver.LookupTXT(ctx, domain)
	lookupError("TXT", txtErr)
	spf := 0
	for _, item := range txt {
		if strings.HasPrefix(strings.ToLower(item), "v=spf1") {
			spf++
			r.observe("SPF", domain, item)
			for _, token := range strings.Fields(item) {
				if token == "+all" || token == "all" {
					r.finding("high", "SPF permits every sender", domain, "The SPF record contains an unrestricted all mechanism.")
				}
			}
		}
	}
	if (txtErr == nil || isNotFound(txtErr)) && spf == 0 {
		r.finding("low", "No SPF policy observed", domain, "No v=spf1 TXT record was returned. This may be intentional for a domain that does not send mail.")
	}
	if spf > 1 {
		r.finding("medium", "Multiple SPF records observed", domain, "Multiple SPF policies can cause a permanent SPF evaluation error.")
	}
	dmarc, dmarcErr := resolver.LookupTXT(ctx, "_dmarc."+domain)
	lookupError("DMARC", dmarcErr)
	policies := 0
	for _, item := range dmarc {
		if !strings.HasPrefix(strings.ToLower(item), "v=dmarc1") {
			continue
		}
		policies++
		r.observe("DMARC", domain, item)
		for _, part := range strings.Split(strings.ToLower(item), ";") {
			if strings.TrimSpace(part) == "p=none" {
				r.finding("low", "DMARC is in monitoring mode", domain, "The p=none policy requests monitoring rather than quarantine or rejection. Review the intended rollout stage.")
			}
		}
	}
	if policies == 0 && (dmarcErr == nil || isNotFound(dmarcErr)) {
		r.finding("low", "No DMARC policy observed at this name", domain, "Organizational-domain inheritance is not evaluated; review the parent domain before treating this as a gap.")
	}
	if policies > 1 {
		r.finding("medium", "Multiple DMARC records observed", domain, "Review duplicate DMARC policies.")
	}
	if ctx.Err() != nil {
		r.Limited = true
		r.gap("DNS diagnostic reached its deadline or was cancelled.")
	}
	r.gap("DNS queries use the system resolver. This contacts DNS infrastructure, does not crawl sites, and is not an exhaustive passive inventory. SPF include chains, DMARC inheritance, DNSSEC and DKIM selectors are not evaluated.")
	return r, nil
}

func isNotFound(err error) bool { e, ok := err.(*net.DNSError); return ok && e.IsNotFound }
