// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Matches sfwebui.py scanexportjsonmulti. Source is parent event data, not an
// event identifier. The export does not contain confidence or risk fields.
type spiderfootEvent struct {
	Data          string          `json:"data"`
	Type          string          `json:"event_type"`
	Module        string          `json:"module"`
	Source        string          `json:"source_data"`
	FalsePositive json.RawMessage `json:"false_positive"`
	ScanTarget    string          `json:"scan_target"`
}

func auditSpiderfoot(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.RunEngine || len(req.Ports) != 0 {
		return nil, fmt.Errorf("SpiderFoot evidence review does not run an engine or accept port selections")
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Target), "."))
	if !validHost(domain) || net.ParseIP(domain) != nil || !strings.Contains(domain, ".") {
		return nil, fmt.Errorf("provide an explicit ASCII target domain for infrastructure scope")
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	if err := checkInput(data); err != nil {
		return nil, err
	}
	events, err := readSpiderfootEvents(ctx, data)
	if err != nil {
		return nil, err
	}
	r := newReport("spiderfoot", "Offline SpiderFoot infrastructure correlation for "+domain+"; imported assertions only.", data)
	r.gap("Supports SpiderFoot scanexportjsonmulti JSON arrays and Type/Data event CSV with optional Module, Source and F/P. Export source_data is parent data, not a unique event ID. No confidence or risk score is inferred.")
	r.gap("No SpiderFoot module execution, live collection, personal profiling or exploit verification. Module counts do not prove independent sources. Source labels can merge distinct original events; relationships are imported assertions, not ownership proof.")
	root := r.node("domain", domain)
	// Addresses require a direct, retained domain-source assertion. This avoids
	// admitting an unrelated IP simply because a multi-target export contains it.
	ips := map[string]bool{}
	for _, event := range events {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fp, err := spiderfootFalsePositive(event.FalsePositive)
		if err != nil {
			return nil, err
		}
		if !fp && spiderfootScanScope(event.ScanTarget, domain) && spiderfootInScope(event.Source, domain) {
			if kind, value := spiderfootEntity(event.Type, event.Data); kind == "ip" {
				ips[value] = true
			}
		}
	}
	type support struct {
		positive, falsePositive bool
		modules                 map[string]bool
		label                   string
	}
	assertions := map[string]*support{}
	for _, event := range events {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !spiderfootScanScope(event.ScanTarget, domain) {
			r.gap("Rows from other scan targets were omitted.")
			continue
		}
		kind, value := spiderfootEntity(event.Type, event.Data)
		if kind == "" {
			r.gap("Unsupported or malformed infrastructure events were omitted, including personal data and banners.")
			continue
		}
		if !spiderfootEntityScope(kind, value, domain, ips) {
			r.gap("Out-of-scope events and addresses without a scoped domain-source assertion were omitted.")
			continue
		}
		fp, _ := spiderfootFalsePositive(event.FalsePositive) // Validated in the first pass.
		key := event.Type + "\x00" + value
		item := assertions[key]
		if item == nil {
			item = &support{modules: map[string]bool{}, label: value}
			assertions[key] = item
		}
		if fp {
			item.falsePositive = true
			r.gap("False-positive rows were excluded from observations and graph edges; conflicting flags are reported separately.")
			continue
		}
		item.positive = true
		if module := spiderfootModule(event.Module); module != "" {
			item.modules[module] = true
		}
		node := r.node(kind, value)
		r.observe(event.Type, value, "Imported SpiderFoot assertion; module "+spiderfootModule(event.Module))
		if kind == "domain" {
			r.edge(root, node, "domain scope contains")
		}
		if sourceKind, sourceValue := spiderfootSource(event.Source); sourceKind != "" && spiderfootEntityScope(sourceKind, sourceValue, domain, ips) {
			r.edge(r.node(sourceKind, sourceValue), node, "reported source of "+event.Type)
		} else {
			r.gap("Missing, unsupported or out-of-scope source labels were not linked. No parent event identifiers are available to resolve dangling provenance.")
		}
		if kind == "tcp endpoint" {
			host, port, _ := net.SplitHostPort(value)
			switch port {
			case "21", "23", "445", "1433", "1521", "3306", "3389", "5432", "5900", "6379", "9200", "27017":
				r.finding("info", "Reported service exposure requires review", value, "An imported TCP_PORT_OPEN event names a commonly administrative or data service port on "+host+". Confirm freshness, intended access and actual service; port number alone does not identify software or establish a vulnerability.")
			}
		}
	}
	keys := make([]string, 0, len(assertions))
	for key := range assertions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		item := assertions[key]
		if item.positive && item.falsePositive {
			r.finding("info", "Conflicting SpiderFoot false-positive flags", item.label, "The same event type and normalized data has both retained and false-positive rows. Review the original scans and timestamps; this is an evidence conflict, not a verified vulnerability.")
		}
		if item.positive && len(item.modules) > 1 {
			r.observe("source diversity", item.label, fmt.Sprintf("%d distinct module labels report this event. Independence is unknown; modules may share upstream data.", len(item.modules)))
		}
	}
	return r, nil
}

func readSpiderfootEvents(ctx context.Context, data []byte) ([]spiderfootEvent, error) {
	var events []spiderfootEvent
	appendEvent := func(event spiderfootEvent) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(events) >= maxRecords {
			return fmt.Errorf("split SpiderFoot exports containing more than 1000 rows")
		}
		if event.Type == "" || event.Data == "" {
			return fmt.Errorf("SpiderFoot rows require event_type and data, or CSV Type and Data")
		}
		if len(event.Data) > 8192 || len(event.Source) > 8192 || len(event.Module) > 128 || len(event.ScanTarget) > 253 {
			return fmt.Errorf("SpiderFoot event fields exceed supported size limits")
		}
		events = append(events, event)
		return nil
	}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) {
		if err := jsonRecords(data, appendEvent); err != nil {
			return nil, err
		}
	} else {
		reader := csv.NewReader(bytes.NewReader(data))
		headers, err := reader.Read()
		if err != nil {
			return nil, fmt.Errorf("expected SpiderFoot JSON array or event CSV")
		}
		columns := map[string]int{}
		for i, header := range headers {
			name := columnName(header)
			if _, exists := columns[name]; exists {
				return nil, fmt.Errorf("duplicate SpiderFoot CSV header")
			}
			columns[name] = i
		}
		if _, ok := columns["type"]; !ok {
			return nil, fmt.Errorf("SpiderFoot CSV requires Type and Data")
		}
		if _, ok := columns["data"]; !ok {
			return nil, fmt.Errorf("SpiderFoot CSV requires Type and Data")
		}
		for {
			row, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("malformed SpiderFoot CSV")
			}
			get := func(name string) string {
				if i, ok := columns[name]; ok {
					return strings.TrimSpace(row[i])
				}
				return ""
			}
			event := spiderfootEvent{Type: get("type"), Data: get("data"), Module: get("module"), Source: get("source")}
			if flag := get("f/p"); flag != "" {
				event.FalsePositive = json.RawMessage(flag)
			}
			if err := appendEvent(event); err != nil {
				return nil, err
			}
		}
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("SpiderFoot export has no events")
	}
	return events, nil
}

func spiderfootFalsePositive(raw json.RawMessage) (bool, error) {
	switch strings.TrimSpace(string(raw)) {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	default:
		return false, fmt.Errorf("SpiderFoot false_positive or F/P must be 0, 1, false or true")
	}
}

func spiderfootModule(value string) string {
	if len(value) > 128 {
		return ""
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return ""
		}
	}
	return value
}

func spiderfootInScope(host, domain string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return validHost(host) && net.ParseIP(host) == nil && (host == domain || strings.HasSuffix(host, "."+domain))
}

func spiderfootScanScope(target, domain string) bool {
	return target == "" || strings.EqualFold(strings.TrimSuffix(target, "."), domain)
}

func spiderfootEntity(kind, value string) (string, string) {
	value = strings.TrimSpace(value)
	if len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00") {
		return "", ""
	}
	switch kind {
	case "INTERNET_NAME", "DOMAIN_NAME":
		value = strings.ToLower(strings.TrimSuffix(value, "."))
		if validHost(value) && net.ParseIP(value) == nil && strings.Contains(value, ".") {
			return "domain", value
		}
	case "IP_ADDRESS", "IPV6_ADDRESS":
		if ip := net.ParseIP(value); ip != nil && ((kind == "IP_ADDRESS") == (ip.To4() != nil)) {
			return "ip", ip.String()
		}
	case "LINKED_URL_INTERNAL":
		u, err := url.Parse(value)
		if err == nil && (u.Scheme == "http" || u.Scheme == "https") && validHost(u.Hostname()) && u.User == nil {
			if u.Port() != "" {
				port, err := strconv.Atoi(u.Port())
				if err != nil || port < 1 || port > 65535 {
					return "", ""
				}
			}
			u.Host = strings.ToLower(u.Host)
			u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
			return "url", u.String()
		}
	case "TCP_PORT_OPEN":
		// Upstream IPv4 port scanner emits ip:port. net.SplitHostPort also
		// accepts unambiguous bracketed IPv6 endpoint exports.
		host, port, err := net.SplitHostPort(value)
		n, portErr := strconv.Atoi(port)
		if err == nil && portErr == nil && n > 0 && n <= 65535 && net.ParseIP(host) != nil {
			return "tcp endpoint", net.JoinHostPort(net.ParseIP(host).String(), strconv.Itoa(n))
		}
	}
	return "", ""
}

func spiderfootSource(value string) (string, string) {
	for _, kind := range []string{"INTERNET_NAME", "IP_ADDRESS", "IPV6_ADDRESS", "LINKED_URL_INTERNAL", "TCP_PORT_OPEN"} {
		if k, v := spiderfootEntity(kind, value); k != "" {
			return k, v
		}
	}
	return "", ""
}

func spiderfootEntityScope(kind, value, domain string, ips map[string]bool) bool {
	switch kind {
	case "domain":
		return spiderfootInScope(value, domain)
	case "ip":
		return ips[value]
	case "url":
		u, err := url.Parse(value)
		return err == nil && spiderfootInScope(u.Hostname(), domain)
	case "tcp endpoint":
		host, _, err := net.SplitHostPort(value)
		return err == nil && ips[host]
	}
	return false
}
