// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"
)

type domainZone struct {
	Origin   string         `json:"origin"`
	Complete bool           `json:"complete"`
	Records  []domainRecord `json:"records"`
}

type domainRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

func auditSpiderdomain(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.RunEngine {
		return nil, fmt.Errorf("spiderdomain upstream identity is unresolved; external engine execution is unavailable")
	}
	if len(req.Ports) != 0 {
		return nil, fmt.Errorf("domain assessment does not accept ports")
	}
	if req.Input != "" {
		if req.Target != "" {
			return nil, fmt.Errorf("choose a live domain or a supplied zone inventory, not both")
		}
		data, err := toolInput(req)
		if err != nil {
			return nil, err
		}
		return auditDomainZone(ctx, data)
	}
	if req.Encoding != "" {
		return nil, fmt.Errorf("encoding requires zone inventory input")
	}
	if !req.Authorized {
		return nil, fmt.Errorf("confirm authorization before DNS assessment")
	}
	r, err := DNS(ctx, req.Target)
	if err != nil {
		return nil, err
	}
	r.Tool = "spiderdomain"
	r.Summary = "Native DNS infrastructure, alias and reverse-name observations for one supplied domain."
	r.gap("Spiderdomain upstream identity is unresolved. This is a native domain assessment, with no upstream engine or parity claim.")
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	enrichDomainDNS(ctx, r, strings.ToLower(strings.TrimSuffix(req.Target, ".")), net.DefaultResolver)
	return r, nil
}

type domainResolver interface {
	LookupCNAME(context.Context, string) (string, error)
	LookupAddr(context.Context, string) ([]string, error)
}

func enrichDomainDNS(ctx context.Context, r *Report, domain string, resolver domainResolver) {
	root := r.node("domain", domain)
	cname, err := resolver.LookupCNAME(ctx, domain)
	if err != nil {
		if !isNotFound(err) {
			r.Limited = true
			r.gap("CNAME lookup failed or timed out.")
		}
	} else if cname = strings.ToLower(strings.TrimSuffix(cname, ".")); cname != domain {
		r.observe("CNAME", domain, cname)
		r.edge(root, r.node("domain", cname), "aliases to")
	} else {
		r.observe("CNAME", domain, "No canonical alias returned")
	}
	count := 0
	// Snapshot the initial evidence because observations below append to the report.
	observations := append([]Observation(nil), r.Observations...)
	for _, obs := range observations {
		if obs.Kind != "A / AAAA" || net.ParseIP(obs.Value) == nil {
			continue
		}
		if count >= 4 {
			r.Limited = true
			r.gap("Reverse DNS was limited to the first four resolved addresses.")
			break
		}
		if ctx.Err() != nil {
			r.Limited = true
			r.gap("DNS enrichment was cancelled or reached its five second deadline.")
			break
		}
		count++
		names, err := resolver.LookupAddr(ctx, obs.Value)
		if err != nil {
			if isNotFound(err) {
				r.observe("PTR", obs.Value, "No reverse name returned")
			} else {
				r.Limited = true
				r.gap("A reverse DNS lookup failed or timed out.")
			}
			continue
		}
		for i, name := range names {
			if i >= 8 {
				r.Limited = true
				r.gap("Reverse DNS names were limited to eight per address.")
				break
			}
			name = strings.ToLower(strings.TrimSuffix(name, "."))
			r.observe("PTR", obs.Value, name)
			r.edge(r.node("ip", obs.Value), r.node("domain", name), "reverse name")
		}
	}
	r.gap("Reverse names are resolver observations, not ownership proof. No forward-confirmed reverse DNS, DNSSEC, live CAA lookup, takeover verification or exhaustive subdomain discovery.")
}

func auditDomainZone(ctx context.Context, data []byte) (*Report, error) {
	if err := checkInput(data); err != nil {
		return nil, err
	}
	var zone domainZone
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&zone); err != nil {
		return nil, fmt.Errorf("provide a JSON zone inventory with origin, complete and records: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("zone inventory must contain exactly one JSON object")
	}
	zone.Origin = strings.ToLower(strings.TrimSuffix(zone.Origin, "."))
	if !validHost(zone.Origin) || net.ParseIP(zone.Origin) != nil || !strings.Contains(zone.Origin, ".") {
		return nil, fmt.Errorf("origin must be one ASCII domain name")
	}
	if len(zone.Records) == 0 || len(zone.Records) > 1000 {
		return nil, fmt.Errorf("provide 1 to 1000 zone records")
	}
	r := newReport("spiderdomain", "Offline DNS zone inventory configuration review; supplied evidence only.", data)
	root := r.node("domain", zone.Origin)
	byName := map[string][]domainRecord{}
	for i, record := range zone.Records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name, err := domainZoneName(record.Name, zone.Origin)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i+1, err)
		}
		record.Name = name
		record.Type = strings.ToUpper(record.Type)
		if len(record.Value) == 0 || len(record.Value) > 4096 || strings.ContainsAny(record.Value, "\x00\r\n") {
			return nil, fmt.Errorf("record %d has an empty, oversized or multiline value", i+1)
		}
		switch record.Type {
		case "A":
			if ip := net.ParseIP(record.Value); ip == nil || ip.To4() == nil {
				return nil, fmt.Errorf("record %d has an invalid IPv4 value", i+1)
			}
		case "AAAA":
			if ip := net.ParseIP(record.Value); ip == nil || ip.To4() != nil {
				return nil, fmt.Errorf("record %d has an invalid IPv6 value", i+1)
			}
		case "CNAME", "NS":
			value, err := domainZoneName(record.Value, zone.Origin)
			if err != nil || strings.Contains(value, "*") {
				return nil, fmt.Errorf("record %d has an invalid DNS target", i+1)
			}
			record.Value = value
		case "TXT", "CAA", "MX", "SOA":
		default:
			return nil, fmt.Errorf("record %d: supported types are A, AAAA, CNAME, NS, TXT, CAA, MX and SOA", i+1)
		}
		if name != zone.Origin && !strings.HasSuffix(name, "."+zone.Origin) {
			return nil, fmt.Errorf("record %d owner is outside the declared origin", i+1)
		}
		byName[name] = append(byName[name], record)
		r.observe(record.Type, name, record.Value)
		r.edge(root, r.node("dns name", name), "zone contains")
		if strings.HasPrefix(name, "*.") {
			r.finding("info", "Wildcard DNS record supplied", name, "Wildcard records expand name resolution. Review whether this matches the intended service scope; this does not establish a vulnerability.")
		}
	}
	owners := make([]string, 0, len(byName))
	for name := range byName {
		owners = append(owners, name)
	}
	sort.Strings(owners)
	for _, name := range owners {
		records := byName[name]
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		aliases := 0
		for _, record := range records {
			if record.Type != "CNAME" {
				continue
			}
			aliases++
			r.edge(r.node("dns name", name), r.node("dns name", record.Value), "aliases to")
			if record.Value == name {
				r.finding("medium", "Self-referencing CNAME", name, "The supplied alias points to itself and cannot resolve to an address.")
			}
			if zone.Complete && strings.HasSuffix(record.Value, "."+zone.Origin) && len(byName[record.Value]) == 0 {
				r.finding("low", "Alias target absent from supplied zone", name, "No owner matching "+record.Value+" appears in the inventory declared complete. Wildcards, delegated zones and external DNS may affect resolution. This does not establish dangling-service takeover.")
			}
		}
		if aliases > 1 {
			r.finding("medium", "Multiple CNAME records at one owner", name, "A CNAME owner should have one canonical target. Duplicate supplied rows also require cleanup.")
		}
		if aliases > 0 && len(records) > aliases {
			r.finding("medium", "CNAME conflicts with other record data", name, "The supplied owner combines a CNAME and other record types. Review authoritative zone validity.")
		}
		if name == zone.Origin {
			auditDomainMail(r, name, records, "spf", zone.Complete)
		}
		if name == "_dmarc."+zone.Origin {
			auditDomainMail(r, name, records, "dmarc", zone.Complete)
		}
	}
	if zone.Complete {
		if len(byName[zone.Origin]) == 0 {
			auditDomainMail(r, zone.Origin, nil, "spf", true)
		}
		if len(byName["_dmarc."+zone.Origin]) == 0 {
			auditDomainMail(r, "_dmarc."+zone.Origin, nil, "dmarc", true)
		}
		caa := 0
		for _, record := range byName[zone.Origin] {
			if record.Type == "CAA" {
				caa++
			}
		}
		if caa == 0 {
			r.observe("CAA coverage", zone.Origin, "No apex CAA record supplied; inherited policy and certificate issuance authorization are not evaluated")
		}
	} else {
		r.Limited = true
		r.gap("Inventory is not declared complete. Absent records and alias targets are not evaluated.")
	}
	r.gap("Records are supplied JSON evidence, not a live zone transfer or BIND parser. MX, SOA and CAA values are retained without protocol validation. Delegation, DNSSEC, effective inherited policy, recursive SPF, alias chains and takeover exploitability are not verified. Spiderdomain upstream identity is unresolved.")
	return r, nil
}

func domainZoneName(value, origin string) (string, error) {
	if value == "@" {
		return origin, nil
	}
	absolute := strings.HasSuffix(value, ".")
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if !absolute {
		value += "." + origin
	}
	if len(value) > 253 {
		return "", fmt.Errorf("DNS name exceeds 253 bytes")
	}
	for i, label := range strings.Split(value, ".") {
		if label == "*" && i == 0 {
			continue
		}
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS name")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", fmt.Errorf("invalid DNS name")
			}
		}
	}
	return value, nil
}

func auditDomainMail(r *Report, name string, records []domainRecord, policy string, complete bool) {
	prefix := "v=spf1"
	if policy == "dmarc" {
		prefix = "v=dmarc1"
	}
	count := 0
	for _, record := range records {
		value := strings.ToLower(strings.TrimSpace(record.Value))
		if record.Type != "TXT" || !(value == prefix || strings.HasPrefix(value, prefix+" ") || strings.HasPrefix(value, prefix+";")) {
			continue
		}
		count++
		if policy == "spf" {
			for _, token := range strings.Fields(value) {
				if token == "+all" || token == "all" {
					r.finding("high", "SPF permits every sender", name, "The supplied SPF policy uses an unrestricted all mechanism.")
				}
			}
		} else {
			foundPolicy := false
			for _, tag := range strings.Split(value, ";") {
				key, val, ok := strings.Cut(strings.TrimSpace(tag), "=")
				if !ok || strings.TrimSpace(key) != "p" {
					continue
				}
				foundPolicy = true
				switch strings.TrimSpace(val) {
				case "none":
					r.finding("low", "DMARC is in monitoring mode", name, "The supplied p=none policy requests monitoring rather than quarantine or rejection.")
				case "reject", "quarantine":
				default:
					r.finding("medium", "Invalid DMARC policy value", name, "The supplied p tag is not none, quarantine or reject.")
				}
			}
			if !foundPolicy {
				r.finding("medium", "DMARC policy tag is missing", name, "A DMARC policy requires a p tag. Other syntax and inherited policy are not evaluated.")
			}
		}
	}
	if count > 1 {
		r.finding("medium", "Multiple "+strings.ToUpper(policy)+" records supplied", name, "Duplicate policy records can cause policy evaluation errors.")
	}
	if complete && count == 0 {
		r.finding("low", "No "+strings.ToUpper(policy)+" policy in supplied complete inventory", name, "Confirm intended mail use and parent-domain policy before treating this as an effective protection gap.")
	}
}
