// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type passiveCertificateRecord struct {
	Names      string `json:"name_value"`
	CommonName string `json:"common_name"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	Issuer     string `json:"issuer_name"`
	Serial     string `json:"serial_number"`
}

// auditPassiveRecon accepts a single authorized domain. Imported public CT
// evidence never triggers requests to discovered names or a third-party API.
func auditPassiveRecon(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.RunEngine {
		return nil, fmt.Errorf("passive reconnaissance does not execute an external engine")
	}
	if !req.Authorized {
		return nil, fmt.Errorf("confirm authorization for the target domain")
	}
	if len(req.Ports) != 0 {
		return nil, fmt.Errorf("passive reconnaissance does not accept ports")
	}
	domain := strings.ToLower(strings.TrimSuffix(req.Target, "."))
	if !validHost(domain) || net.ParseIP(domain) != nil || !strings.Contains(domain, ".") {
		return nil, fmt.Errorf("provide one ASCII domain name without a URL; use punycode for international names")
	}
	if req.Input != "" {
		data, err := toolInput(req)
		if err != nil {
			return nil, err
		}
		return auditPassiveCertificates(ctx, domain, data, time.Now().UTC())
	}
	if req.Encoding != "" {
		return nil, fmt.Errorf("encoding requires certificate-transparency JSON input")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r, err := DNS(ctx, domain)
	if err != nil {
		return nil, err
	}
	r.Tool = "passive-recon"
	r.Summary = "DNS and verified public TLS certificate observations for one authorized domain."
	r.gap("DNS queries and one TLS handshake on port 443 contact the supplied domain's infrastructure. Discovered names are never contacted.")
	r.gap("No certificate-transparency feed was queried. Supply a public CT JSON export to review historical certificate names. No crawling, brute-force or complete asset inventory.")
	cert, err := passiveTLSCertificate(ctx, domain)
	if err != nil {
		r.Limited = true
		r.gap("The public TLS certificate could not be collected with normal hostname and trust verification; no certificate evidence was accepted.")
		return r, nil
	}
	r.observe("TLS certificate validity", domain, cert.NotBefore.UTC().Format(time.RFC3339)+" to "+cert.NotAfter.UTC().Format(time.RFC3339))
	r.observe("TLS certificate checked at", domain, r.CreatedAt.Format(time.RFC3339))
	seen := map[string]bool{}
	root := r.node("domain", domain)
	for i, raw := range cert.DNSNames {
		if i >= maxRecords {
			r.limit()
			break
		}
		name, wildcard := passiveScopedName(raw, domain)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		kind := "TLS certificate SAN"
		if wildcard {
			kind = "TLS certificate wildcard SAN"
		}
		r.observe(kind, name, "Present on the verified certificate; does not establish a live service at this name.")
		r.edge(root, r.node("domain", name), "certificate name")
	}
	r.gap("Only the verified leaf certificate's in-scope DNS SANs are retained. A wildcard is a certificate pattern, not an enumerated host. Certificate issuer, off-scope names and certificate bodies are omitted.")
	return r, nil
}

// Require global, non-private addresses and pin the address before TLS dialing.
// ServerName and default trust roots retain normal certificate verification.
func passiveTLSCertificate(ctx context.Context, domain string) (*passiveLeafCertificate, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", domain)
	if err != nil || len(addresses) == 0 {
		return nil, fmt.Errorf("public target resolution failed")
	}
	for _, address := range addresses {
		if !passivePublicAddress(address) {
			return nil, fmt.Errorf("target does not resolve exclusively to public addresses")
		}
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 4 * time.Second}, Config: &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12}}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(addresses[0].Unmap().String(), "443"))
	if err != nil {
		return nil, fmt.Errorf("verified TLS handshake failed")
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("TLS connection unavailable")
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return nil, fmt.Errorf("no verified certificate")
	}
	cert := state.PeerCertificates[0]
	return &passiveLeafCertificate{cert.DNSNames, cert.NotBefore, cert.NotAfter}, nil
}

type passiveLeafCertificate struct {
	DNSNames  []string
	NotBefore time.Time
	NotAfter  time.Time
}

func passivePublicAddress(address netip.Addr) bool {
	address = address.Unmap()
	return diagnosticAddress(address) && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !netip.MustParsePrefix("100.64.0.0/10").Contains(address)
}

func passiveScopedName(raw, domain string) (string, bool) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	wildcard := strings.HasPrefix(name, "*.")
	base := strings.TrimPrefix(name, "*.")
	if !validHost(base) || net.ParseIP(base) != nil || (base != domain && !strings.HasSuffix(base, "."+domain)) {
		return "", false
	}
	return name, wildcard
}

func passiveCertificateTime(value string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05", "2006-01-02"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func auditPassiveCertificates(ctx context.Context, domain string, data []byte, now time.Time) (*Report, error) {
	if err := checkInput(data); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('[') {
		return nil, fmt.Errorf("provide a CT JSON array of certificate records")
	}
	r := newReport("passive-recon", "", data)
	r.gap("Historical CT evidence only. Certificate names, issuance and expiry do not establish current DNS resolution, a live service or a vulnerability. No network calls or external engine execution.")
	r.gap("Coverage depends on the supplied export; absence is not proof that no certificate or subdomain exists. Issuer names, serials, off-scope names and raw certificates are omitted.")
	r.observe("CT reviewed at", domain, now.UTC().Format(time.RFC3339))
	root := r.node("domain", domain)
	seenNames := map[string]bool{}
	seenCertificates := map[string]bool{}
	records, matched, excluded, nameTokens := 0, 0, 0, 0
	truncated := false
	for d.More() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if records >= maxRecords {
			truncated = true
			r.limit()
			r.gap("Only the first 1,000 CT certificate records were parsed. Remaining JSON was not validated.")
			break
		}
		var cert passiveCertificateRecord
		if err := d.Decode(&cert); err != nil {
			return nil, fmt.Errorf("invalid CT certificate record schema")
		}
		records++
		// Iterate newline SANs without unbounded split allocations; CN is a
		// separate source even when it duplicates a SAN.
		inScope := map[string]bool{}
		remaining := cert.Names
		for n := 0; ; n++ {
			if nameTokens >= 10000 {
				r.Limited = true
				r.gap("The 10,000 total SAN-token review limit was reached; remaining SANs were omitted.")
				break
			}
			if n >= maxRecords {
				r.limit()
				break
			}
			part, rest, more := strings.Cut(remaining, "\n")
			nameTokens++
			if name, wildcard := passiveScopedName(part, domain); name != "" {
				inScope[name] = wildcard
			}
			if !more {
				break
			}
			remaining = rest
		}
		if name, wildcard := passiveScopedName(cert.CommonName, domain); name != "" {
			inScope[name] = wildcard
		}
		if len(inScope) == 0 {
			excluded++
			continue
		}
		matched++
		// Hash identity rather than storing arbitrary source serial/issuer text.
		identity := digest([]byte(cert.Serial + "\x00" + cert.Issuer + "\x00" + cert.NotBefore + "\x00" + cert.NotAfter + "\x00" + cert.Names + "\x00" + cert.CommonName))[:24]
		if seenCertificates[identity] {
			continue
		}
		seenCertificates[identity] = true
		certNode := r.node("certificate", "CT-"+identity)
		ordered := make([]string, 0, len(inScope))
		for name := range inScope {
			ordered = append(ordered, name)
		}
		sort.Strings(ordered)
		for _, name := range ordered {
			wildcard := inScope[name]
			if !seenNames[name] {
				if len(seenNames) >= maxRecords {
					r.limit()
					break
				}
				seenNames[name] = true
				kind := "CT certificate name"
				if wildcard {
					kind = "CT wildcard pattern"
				}
				r.observe(kind, name, "Historical certificate assertion; current ownership and liveness are unverified.")
			}
			nameNode := r.node("domain", name)
			r.edge(root, nameNode, "in-scope certificate name")
			r.edge(certNode, nameNode, "names")
		}
		before, beforeOK := passiveCertificateTime(cert.NotBefore)
		after, afterOK := passiveCertificateTime(cert.NotAfter)
		if !beforeOK || !afterOK || after.Before(before) {
			r.Limited = true
			r.gap("Some in-scope certificate validity dates were missing, invalid or reversed; freshness could not be assessed for those records.")
			continue
		}
		r.observe("CT validity interval", "CT-"+identity, before.Format(time.RFC3339)+" to "+after.Format(time.RFC3339))
		status := "Validity interval includes review time; deployment remains unverified."
		if after.Before(now) {
			status = "Expired historical certificate; this does not establish an expired certificate on the live endpoint."
		} else if before.After(now) {
			status = "Validity begins in the future; verify source timestamps."
		}
		r.observe("CT freshness", "CT-"+identity, status)
	}
	if !truncated {
		if _, err := d.Token(); err != nil {
			return nil, fmt.Errorf("invalid CT array terminator")
		}
		if err := d.Decode(new(any)); err != io.EOF {
			return nil, fmt.Errorf("unexpected data after CT array")
		}
	}
	r.Summary = fmt.Sprintf("Reviewed %d CT records: %d in-scope records, %d distinct certificate names; %d records excluded without retaining their names.", records, matched, len(seenNames), excluded)
	return r, nil
}
