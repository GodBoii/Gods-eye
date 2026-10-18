// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

type reconNGRecord struct {
	Host   string `json:"host"`
	IP     string `json:"ip_address"`
	Source string `json:"source,omitempty"`
}

type reconNGHost struct {
	addresses map[string]bool
	sources   map[string]map[string]bool
}

// auditReconNG compares supplied infrastructure snapshots, without running modules.
// Required JSON fields are domain, before and after. Each row requires host and
// ip_address; source is an optional, non-personal inventory identifier.
func auditReconNG(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.RunEngine {
		return nil, fmt.Errorf("recon-ng engine execution is unsupported; supply inventory snapshot JSON")
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	if err := checkInput(data); err != nil {
		return nil, err
	}
	var input struct {
		Domain string           `json:"domain"`
		Before *[]reconNGRecord `json:"before"`
		After  *[]reconNGRecord `json:"after"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		return nil, fmt.Errorf("invalid recon-ng inventory JSON: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("provide exactly one inventory JSON object")
	}
	domain, ok := reconNGDomain(input.Domain)
	if !ok {
		return nil, fmt.Errorf("domain must be a DNS domain without a wildcard, URL or IP address")
	}
	if req.Target != "" {
		target, valid := reconNGDomain(req.Target)
		if !valid || target != domain {
			return nil, fmt.Errorf("target must match the inventory domain")
		}
	}
	if input.Before == nil || input.After == nil {
		return nil, fmt.Errorf("before and after must both be JSON arrays, including when empty")
	}
	if len(*input.Before)+len(*input.After) > maxRecords {
		return nil, fmt.Errorf("inventory exceeds the combined 1,000-record limit")
	}
	before, err := reconNGSnapshot(ctx, domain, *input.Before)
	if err != nil {
		return nil, fmt.Errorf("before snapshot: %w", err)
	}
	after, err := reconNGSnapshot(ctx, domain, *input.After)
	if err != nil {
		return nil, fmt.Errorf("after snapshot: %w", err)
	}
	r := newReport("recon-ng", "", data)
	r.gap("Offline comparison of supplied snapshots only; no recon-ng modules, network discovery, DNS verification or personal-data enrichment.")
	r.gap("A removed row means absent from the supplied snapshot, not confirmed decommissioning. Address changes and source disagreements do not prove stale DNS, dangling IP takeover or exploitability. Multiple addresses may be legitimate.")
	hostSet := map[string]bool{}
	for host := range before {
		hostSet[host] = true
	}
	for host := range after {
		hostSet[host] = true
	}
	added, removed, changed := 0, 0, 0
	for _, host := range reconNGKeys(hostSet) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		old, previous := before[host]
		current, present := after[host]
		switch {
		case !previous:
			added++
			r.observe("inventory host added", host, reconNGAddresses(current))
		case !present:
			removed++
			r.observe("inventory host absent", host, "Previously observed addresses: "+reconNGAddresses(old)+". Absence is not proof of decommissioning.")
		case reconNGAddresses(old) != reconNGAddresses(current):
			changed++
			r.observe("inventory addresses changed", host, reconNGAddresses(old)+" -> "+reconNGAddresses(current))
		default:
			r.observe("inventory host unchanged", host, reconNGAddresses(current))
		}
		for _, snapshot := range []struct {
			name  string
			hosts map[string]reconNGHost
		}{{"before", before}, {"after", after}} {
			h, exists := snapshot.hosts[host]
			if !exists {
				continue
			}
			hostID := r.node("host", host)
			for _, ip := range reconNGKeys(h.addresses) {
				r.edge(hostID, r.node("ip", ip), "observed in "+snapshot.name)
			}
			var baseline string
			divergent := false
			for _, source := range reconNGKeys(h.sources) {
				addresses := strings.Join(reconNGKeys(h.sources[source]), ", ")
				// Empty source is explicitly unknown and cannot establish provenance conflict.
				if source == "" {
					continue
				}
				if baseline == "" {
					baseline = addresses
				} else if baseline != addresses {
					divergent = true
				}
				r.observe("inventory source addresses", host, snapshot.name+" / "+source+": "+addresses)
			}
			if divergent {
				r.finding("info", "Inventory sources report different address sets", host, snapshot.name+" snapshot sources disagree. Review collection timing and multi-address hosting before treating this as an error.")
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.Summary = fmt.Sprintf("Compared %d baseline and %d current hosts: %d added, %d absent, %d with address changes.", len(before), len(after), added, removed, changed)
	return r, nil
}

func reconNGSnapshot(ctx context.Context, domain string, rows []reconNGRecord) (map[string]reconNGHost, error) {
	hosts := map[string]reconNGHost{}
	for i, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		host, valid := reconNGDomain(row.Host)
		if !valid || (host != domain && !strings.HasSuffix(host, "."+domain)) {
			return nil, fmt.Errorf("row %d host is invalid or outside the domain scope", i+1)
		}
		ip, err := netip.ParseAddr(row.IP)
		if err != nil || ip.Zone() != "" {
			return nil, fmt.Errorf("row %d requires an exact IP address without a zone or CIDR", i+1)
		}
		if len(row.Source) > 64 {
			return nil, fmt.Errorf("row %d source identifier exceeds 64 bytes", i+1)
		}
		for _, c := range row.Source {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-", c)) {
				return nil, fmt.Errorf("row %d source must be an infrastructure inventory identifier", i+1)
			}
		}
		h, exists := hosts[host]
		if !exists {
			h = reconNGHost{map[string]bool{}, map[string]map[string]bool{}}
		}
		address := ip.Unmap().String()
		h.addresses[address] = true
		if h.sources[row.Source] == nil {
			h.sources[row.Source] = map[string]bool{}
		}
		h.sources[row.Source][address] = true
		hosts[host] = h
	}
	return hosts, nil
}

func reconNGDomain(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if len(value) == 0 || len(value) > 253 || !strings.Contains(value, ".") {
		return "", false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	return value, true
}

func reconNGKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func reconNGAddresses(host reconNGHost) string {
	return strings.Join(reconNGKeys(host.addresses), ", ")
}
