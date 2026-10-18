// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// BBOT event JSON exports use parent event IDs and resolved_hosts. Older
// exports may call the parent ID source. Neither is a host ownership claim.
type bbotAuditEvent struct {
	ID            string          `json:"id"`
	Parent        string          `json:"parent"`
	Source        string          `json:"source"`
	Type          string          `json:"type"`
	Data          json.RawMessage `json:"data"`
	Distance      *int            `json:"scope_distance"`
	Tags          []string        `json:"tags"`
	Resolved      []string        `json:"resolved_hosts"`
	FalsePositive bool            `json:"false_positive"`
	Excluded      bool            `json:"excluded"`
}

type bbotAuditEntity struct{ kind, value, host string }

func auditBBOT(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.RunEngine || len(req.Ports) != 0 {
		return nil, fmt.Errorf("BBOT export review does not execute a scanner or accept ports")
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Target), "."))
	if !validHost(domain) || net.ParseIP(domain) != nil || !strings.Contains(domain, ".") {
		return nil, fmt.Errorf("provide an explicit ASCII root domain for BBOT scope")
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	if err := checkInput(data); err != nil {
		return nil, err
	}
	events := []bbotAuditEvent{}
	err = jsonRecords(data, func(e bbotAuditEvent) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(events) >= maxRecords {
			return fmt.Errorf("split BBOT exports containing more than 1000 events")
		}
		if e.Type == "" || len(e.Type) > 128 || len(e.Data) > 8192 || len(e.ID) > 256 || len(e.Parent) > 256 || len(e.Source) > 256 || len(e.Resolved) > 64 || len(e.Tags) > 64 {
			return fmt.Errorf("BBOT event fields exceed supported limits or lack a type")
		}
		for _, tag := range e.Tags {
			if len(tag) > 128 {
				return fmt.Errorf("BBOT tag exceeds 128 bytes")
			}
		}
		for _, ip := range e.Resolved {
			if len(ip) > 64 {
				return fmt.Errorf("BBOT resolved address exceeds 64 bytes")
			}
		}
		events = append(events, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("BBOT export has no events")
	}
	r := newReport("bbot", "Offline BBOT discovery provenance and coverage for "+domain+"; supplied evidence only.", data)
	r.gap("Supports JSON arrays and JSONL infrastructure events with parent IDs, legacy source IDs and resolved_hosts. All relationships are imported assertions; no live recursion, scanner execution or vulnerability verification occurs.")
	r.gap("Coverage describes supplied evidence, not scan completeness. Missing service or resolution evidence does not prove that a host is unresolved or secure. URL queries, credentials, fragments, unsupported personal data and banners are omitted; paths can still be sensitive.")
	inScope := func(host string) bool { return host == domain || strings.HasSuffix(host, "."+domain) }
	entities := make([]bbotAuditEntity, len(events))
	ids := map[string]int{}
	ambiguous := map[string]bool{}
	eligible := make([]bool, len(events))
	// Detect conflicting IDs before creating edges; never select an arbitrary parent.
	for i, e := range events {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if e.ID != "" {
			if old, ok := ids[e.ID]; ok {
				a, b := events[old], e
				if string(a.Data) != string(b.Data) || a.Type != b.Type || a.Parent != b.Parent || a.Source != b.Source || bbotExcluded(a) != bbotExcluded(b) {
					ambiguous[e.ID] = true
					r.gap("Conflicting event IDs were excluded from provenance and coverage.")
				}
			} else {
				ids[e.ID] = i
			}
		}
		if bbotExcluded(e) {
			r.gap("Excluded, false-positive, affiliate or nonzero-distance events were omitted.")
			continue
		}
		entities[i] = bbotEntity(e)
		if entities[i].kind == "" {
			r.gap("Unsupported or malformed events were omitted, including findings, bodies and personal data.")
			continue
		}
		eligible[i] = true
	}
	// Admit addresses only through a scoped name's explicit resolution assertion,
	// or an IP event whose parent is a retained scoped name event.
	ips := map[string]bool{}
	for i, e := range events {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !eligible[i] || ambiguous[e.ID] {
			continue
		}
		ent := entities[i]
		if net.ParseIP(ent.host) == nil && inScope(ent.host) {
			for _, v := range e.Resolved {
				if ip := net.ParseIP(v); ip != nil {
					ips[ip.String()] = true
				}
			}
		}
		if ent.kind == "ip" {
			parent := e.Parent
			if parent == "" {
				parent = e.Source
			}
			if p, ok := ids[parent]; ok && !ambiguous[parent] && eligible[p] && entities[p].kind == "domain" && inScope(entities[p].host) {
				ips[ent.host] = true
			}
		}
	}
	nodes := make([]string, len(events))
	names, resolved, services := map[string]bool{}, map[string]bool{}, map[string]bool{}
	seen := map[string]bool{}
	for i, e := range events {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !eligible[i] || ambiguous[e.ID] {
			continue
		}
		ent := entities[i]
		if !(net.ParseIP(ent.host) == nil && inScope(ent.host) || ips[ent.host]) {
			r.gap("Out-of-scope names and addresses without scoped resolution evidence were omitted.")
			continue
		}
		nodes[i] = r.node(ent.kind, ent.value)
		key := e.Type + "\x00" + ent.value
		if !seen[key] {
			r.observe(e.Type, ent.value, "Imported BBOT infrastructure assertion.")
			seen[key] = true
		}
		if net.ParseIP(ent.host) == nil {
			names[ent.host] = true
			for _, v := range e.Resolved {
				if ip := net.ParseIP(v); ip != nil {
					resolved[ent.host] = true
					r.edge(r.node("domain", ent.host), r.node("ip", ip.String()), "reported resolution")
				}
			}
		}
		if e.Type == "URL" || e.Type == "OPEN_TCP_PORT" {
			services[ent.host] = true
		}
	}
	for i, e := range events {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if nodes[i] == "" {
			continue
		}
		parent := e.Parent
		if parent == "" {
			parent = e.Source
		}
		if parent == "" {
			r.gap("Some events lack parent IDs; recursive provenance cannot be reconstructed for them.")
			continue
		}
		p, ok := ids[parent]
		if !ok || ambiguous[parent] || nodes[p] == "" {
			r.gap("Dangling, conflicting, excluded or out-of-scope parent IDs were not linked.")
			continue
		}
		if p == i || nodes[p] == nodes[i] {
			r.gap("Self-referential provenance was omitted.")
			continue
		}
		r.edge(nodes[p], nodes[i], "reported discovery parent")
		if entities[i].kind == "ip" && entities[p].kind == "domain" {
			resolved[entities[p].host] = true
		}
	}
	// Service evidence on a resolved address does not establish the virtual
	// host's application coverage, so domain frontiers require host evidence.
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	for _, name := range ordered {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !resolved[name] {
			r.observe("coverage frontier", name, "No retained address-resolution evidence supplied; review DNS collection coverage.")
		}
		if !services[name] {
			r.observe("coverage frontier", name, "No retained URL visit or open TCP service evidence supplied; review service collection coverage.")
		}
	}
	r.observe("coverage summary", domain, fmt.Sprintf("%d scoped host names and %d deduplicated infrastructure assertions retained. Frontier items are evidence gaps, not vulnerabilities.", len(names), len(seen)))
	return r, nil
}

func bbotExcluded(e bbotAuditEvent) bool {
	if e.FalsePositive || e.Excluded || e.Distance != nil && *e.Distance != 0 {
		return true
	}
	for _, tag := range e.Tags {
		switch strings.ToLower(tag) {
		case "false-positive", "false_positive", "excluded", "affiliate", "out-of-scope":
			return true
		}
	}
	return false
}

func bbotEntity(e bbotAuditEvent) bbotAuditEntity {
	var value string
	if json.Unmarshal(e.Data, &value) != nil || len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00") {
		return bbotAuditEntity{}
	}
	value = strings.TrimSpace(value)
	switch e.Type {
	case "DNS_NAME", "DNS_NAME_UNRESOLVED":
		value = strings.ToLower(strings.TrimSuffix(value, "."))
		if validHost(value) && net.ParseIP(value) == nil && strings.Contains(value, ".") {
			return bbotAuditEntity{"domain", value, value}
		}
	case "IP_ADDRESS":
		if ip := net.ParseIP(value); ip != nil {
			return bbotAuditEntity{"ip", ip.String(), ip.String()}
		}
	case "URL", "URL_UNVERIFIED":
		u, err := url.Parse(value)
		if err == nil && (u.Scheme == "http" || u.Scheme == "https") && validHost(u.Hostname()) && u.User == nil {
			if port := u.Port(); port != "" {
				n, err := strconv.Atoi(port)
				if err != nil || n < 1 || n > 65535 {
					return bbotAuditEntity{}
				}
			}
			u.Host = strings.ToLower(u.Host)
			u.RawQuery = ""
			u.Fragment = ""
			u.RawFragment = ""
			u.ForceQuery = false
			return bbotAuditEntity{"url", u.String(), strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))}
		}
	case "OPEN_TCP_PORT":
		host, port, err := net.SplitHostPort(value)
		n, pErr := strconv.Atoi(port)
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if err == nil && pErr == nil && n > 0 && n <= 65535 && validHost(host) {
			if ip := net.ParseIP(host); ip != nil {
				host = ip.String()
			}
			return bbotAuditEntity{"tcp endpoint", net.JoinHostPort(host, strconv.Itoa(n)), host}
		}
	}
	return bbotAuditEntity{}
}
