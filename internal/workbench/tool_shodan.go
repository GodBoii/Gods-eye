// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var shodanProductPattern = regexp.MustCompile(`^[A-Za-z0-9 ._+()/:-]*$`)
var shodanCVEPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

type shodanBanner struct {
	IP        string          `json:"ip_str"`
	Port      int             `json:"port"`
	Transport string          `json:"transport"`
	Product   string          `json:"product"`
	Version   string          `json:"version"`
	Timestamp string          `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
	Matches   json.RawMessage `json:"matches"`
	Vulns     json.RawMessage `json:"vulns"`
	Total     *int            `json:"total"`
	SSL       *struct {
		Cert struct {
			Expires string `json:"expires"`
		} `json:"cert"`
	} `json:"ssl"`
	FTP *struct {
		Anonymous *bool `json:"anonymous"`
	} `json:"ftp"`
	SMB *struct {
		Anonymous *bool `json:"anonymous"`
	} `json:"smb"`
}

// auditShodan reviews indexed evidence without making requests or retaining raw banners.
func auditShodan(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.RunEngine {
		return nil, fmt.Errorf("Shodan engine execution is unsupported; supply a JSON export")
	}
	var scope net.IP
	if req.Target != "" {
		scope = net.ParseIP(strings.TrimSpace(req.Target))
		if scope == nil {
			return nil, fmt.Errorf("Shodan target filter must be one exact IP address")
		}
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	if err := checkInput(data); err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("Shodan JSON input is empty")
	}
	r := newReport("shodan", "", data)
	r.gap("Offline indexed evidence only. No API calls, live validation or exploitation. Shodan verified=true is a source assertion, not independent verification.")
	r.gap("Only CVE assertions, certificate expiry and explicit FTP/SMB anonymous flags are analyzed; other authentication models and banner bodies are not inspected.")
	records, matched, skipped := 0, 0, 0
	var consume func(json.RawMessage, string, bool) error
	consume = func(raw json.RawMessage, inheritedIP string, nested bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if records >= 10000 {
			r.Limited = true
			r.gap("The 10,000 input-record limit was reached; remaining records were not analyzed.")
			return nil
		}
		records++
		var b shodanBanner
		if err := json.Unmarshal(raw, &b); err != nil {
			return fmt.Errorf("invalid Shodan record schema")
		}
		if b.IP == "" {
			b.IP = inheritedIP
		}
		var children []json.RawMessage
		wrapper := bytes.TrimSpace(b.Matches)
		if len(wrapper) == 0 || bytes.Equal(wrapper, []byte("null")) {
			wrapper = bytes.TrimSpace(b.Data)
		}
		if len(wrapper) > 0 && wrapper[0] == '[' {
			if nested {
				return fmt.Errorf("recursive Shodan wrappers are unsupported")
			}
			if err := json.Unmarshal(wrapper, &children); err != nil {
				return fmt.Errorf("invalid Shodan wrapper")
			}
			if b.Total != nil && *b.Total > len(children) {
				r.Limited = true
				r.gap("Search export total exceeds included matches; additional indexed results are missing.")
			}
			for _, child := range children {
				if records >= 10000 {
					r.Limited = true
					r.gap("The 10,000 input-record limit was reached; remaining records were not analyzed.")
					break
				}
				if err := consume(child, b.IP, true); err != nil {
					return err
				}
			}
			return nil
		}
		ip := net.ParseIP(b.IP)
		if ip == nil || b.Port < 1 || b.Port > 65535 {
			return fmt.Errorf("Shodan service requires ip_str and a port from 1 to 65535")
		}
		if scope != nil && !scope.Equal(ip) {
			skipped++
			return nil
		}
		if b.Transport == "" {
			b.Transport = "tcp"
		}
		if b.Transport != "tcp" && b.Transport != "udp" {
			return fmt.Errorf("Shodan transport must be tcp or udp")
		}
		matched++
		if len(r.Findings)+len(r.Observations) >= 1000 {
			r.limit()
			return nil
		}
		target := b.Transport + "://" + net.JoinHostPort(ip.String(), strconv.Itoa(b.Port))
		stamp, ok := shodanTime(b.Timestamp)
		freshness := "timestamp missing or invalid"
		if ok {
			freshness = "observed=" + stamp.UTC().Format(time.RFC3339)
			if r.CreatedAt.Sub(stamp) > 30*24*time.Hour {
				freshness += "; stale (>30 days)"
				r.gap("Some observations are older than 30 days; current exposure requires fresh evidence.")
			}
			if stamp.After(r.CreatedAt.Add(5 * time.Minute)) {
				freshness += "; future timestamp"
				r.gap("Future observation timestamps cannot establish evidence freshness.")
			}
		} else {
			r.gap("Some records have missing or invalid observation timestamps; freshness cannot be established.")
		}
		r.observe("indexed service", target, "product="+shodanToken(b.Product)+" version="+shodanToken(b.Version)+"; "+freshness)
		add := func(severity, title, detail string) {
			if len(r.Findings)+len(r.Observations) >= 1000 {
				r.limit()
				return
			}
			r.finding(severity, title, target, detail+"; "+freshness+". Verify current configuration before remediation.")
		}
		if err := shodanCVEs(ctx, r, b.Vulns, func(cve string, verified bool) {
			if verified {
				add("medium", cve+" reported verified by Shodan", "Source metadata verified=true; independently unverified. Confirm installed version and vendor remediation")
			} else {
				add("info", cve+" unverified candidate", "No explicit verified=true source assertion. Version matching alone does not prove vulnerability")
			}
		}); err != nil {
			return err
		}
		if b.SSL != nil && b.SSL.Cert.Expires != "" {
			expires, valid := shodanTime(b.SSL.Cert.Expires)
			if !valid {
				r.gap("A certificate expiry timestamp was invalid and omitted.")
			} else if ok && expires.Before(stamp) {
				add("medium", "Certificate expired at indexed observation", "ssl.cert.expires="+expires.UTC().Format(time.RFC3339))
			} else if expires.Before(r.CreatedAt) {
				add("info", "Indexed certificate expiry has passed", "ssl.cert.expires="+expires.UTC().Format(time.RFC3339)+"; the certificate may since have been replaced")
			}
		}
		if b.FTP != nil && b.FTP.Anonymous != nil && *b.FTP.Anonymous {
			add("medium", "Indexed FTP anonymous access", "Explicit ftp.anonymous=true metadata; anonymous access may be intentional. Review access policy and writable paths")
		}
		if b.SMB != nil && b.SMB.Anonymous != nil && *b.SMB.Anonymous {
			add("medium", "Indexed SMB anonymous access", "Explicit smb.anonymous=true metadata. Review guest access policy and share permissions")
		}
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if bytes.TrimSpace(data)[0] == '[' {
		if _, err := decoder.Token(); err != nil {
			return nil, fmt.Errorf("invalid Shodan JSON array")
		}
		for decoder.More() {
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				return nil, fmt.Errorf("invalid Shodan JSON record")
			}
			if err := consume(raw, "", false); err != nil {
				return nil, err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return nil, fmt.Errorf("invalid Shodan JSON array")
		}
		var extra json.RawMessage
		if err := decoder.Decode(&extra); err != io.EOF {
			return nil, fmt.Errorf("unexpected trailing Shodan JSON")
		}
	} else {
		for {
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err == io.EOF {
				break
			} else if err != nil {
				return nil, fmt.Errorf("invalid Shodan JSON record")
			}
			if err := consume(raw, "", false); err != nil {
				return nil, err
			}
		}
	}
	if skipped > 0 {
		r.gap("Out-of-scope IP records were omitted by the exact IP filter.")
	}
	if matched == 0 {
		r.gap("No in-scope service records were available; this does not establish absence of exposure.")
	}
	r.Summary = fmt.Sprintf("Received %d in-scope indexed services; emitted %d review findings within collection limits. No live verification performed.", matched, len(r.Findings))
	return r, nil
}

func shodanToken(value string) string {
	if len(value) > 96 || !shodanProductPattern.MatchString(value) {
		return "omitted"
	}
	for _, marker := range []string{"password", "secret", "token", "authorization", "bearer", "cookie"} {
		if strings.Contains(strings.ToLower(value), marker) {
			return "omitted"
		}
	}
	return value
}

func shodanTime(value string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "20060102150405Z"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func shodanCVEs(ctx context.Context, r *Report, raw json.RawMessage, consume func(string, bool)) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	fields := make(map[string]json.RawMessage)
	if raw[0] == '[' {
		var names []string
		if err := json.Unmarshal(raw, &names); err != nil {
			return fmt.Errorf("invalid Shodan vulnerability list")
		}
		for _, name := range names {
			fields[name] = nil
		}
	} else if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("invalid Shodan vulnerability metadata")
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > 10000 {
		r.Limited = true
		r.gap("CVE metadata is limited to 10,000 distinct identifiers per service; additional identifiers were omitted.")
		names = names[:10000]
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !shodanCVEPattern.MatchString(name) {
			return fmt.Errorf("invalid Shodan CVE identifier")
		}
		verified := false
		if len(fields[name]) > 0 && !bytes.Equal(fields[name], []byte("null")) {
			var meta struct {
				Verified *bool `json:"verified"`
			}
			if err := json.Unmarshal(fields[name], &meta); err != nil {
				return fmt.Errorf("invalid Shodan CVE verification metadata")
			}
			verified = meta.Verified != nil && *meta.Verified
		}
		consume(name, verified)
	}
	return nil
}
