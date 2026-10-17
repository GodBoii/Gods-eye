// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func importNuclei(r *Report, data []byte) error {
	type event struct {
		ID            string `json:"template-id"`
		Host          string `json:"host"`
		Matched       string `json:"matched-at"`
		MatcherStatus *bool  `json:"matcher-status"`
		Info          struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
		} `json:"info"`
	}
	return jsonRecords(data, func(e event) error {
		if e.ID == "" || e.Info.Name == "" {
			return fmt.Errorf("record is missing template-id or info.name")
		}
		if e.MatcherStatus != nil && !*e.MatcherStatus {
			r.observe("non-match", e.Host, e.ID)
			return nil
		}
		target := e.Matched
		if target == "" {
			target = e.Host
		}
		if target == "" {
			return fmt.Errorf("matched record needs host or matched-at")
		}
		r.finding(e.Info.Severity, e.Info.Name, target, "Nuclei template: "+e.ID+". Verify the template match before remediation.")
		r.node("asset", target)
		return nil
	})
}

func importHAR(r *Report, data []byte) error {
	var doc struct {
		Log *struct {
			Version string `json:"version"`
			Entries []struct {
				Request struct {
					Method string `json:"method"`
					URL    string `json:"url"`
				} `json:"request"`
				Response struct {
					Status  int `json:"status"`
					Headers []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"headers"`
				} `json:"response"`
				Time float64 `json:"time"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := decodeJSON(data, &doc); err != nil {
		return err
	}
	if doc.Log == nil || doc.Log.Version == "" || doc.Log.Entries == nil {
		return fmt.Errorf("expected HAR log.version and log.entries")
	}
	for _, e := range doc.Log.Entries {
		u, err := url.Parse(e.Request.URL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || e.Request.Method == "" {
			return fmt.Errorf("entry has an invalid HTTP request URL or method")
		}
		if e.Response.Status < 0 || e.Response.Status > 599 {
			return fmt.Errorf("invalid HTTP response status")
		}
		target := Target(e.Request.URL)
		r.observe("HTTP exchange", target, fmt.Sprintf("%s · status %d · %.1f ms", e.Request.Method, e.Response.Status, e.Time))
		r.edge(r.node("domain", u.Hostname()), r.node("url", target), "serves")
		if u.Scheme == "http" {
			r.finding("medium", "Unencrypted HTTP exchange", target, "The recorded request used HTTP. Confirm whether the application should require HTTPS.")
		}
		headers := make(map[string]bool)
		for _, h := range e.Response.Headers {
			headers[strings.ToLower(h.Name)] = true
		}
		if e.Response.Status >= 200 && e.Response.Status < 400 && u.Scheme == "https" && !headers["strict-transport-security"] {
			r.finding("low", "HSTS absent from recorded response", u.Scheme+"://"+u.Host, "This is an observation from a supplied archive, not a live policy test.")
		}
		if len(r.Observations) >= maxRecords {
			r.limit()
			break
		}
	}
	r.gap("HAR analysis is offline. Requests are never replayed. Header presence is not proof of an effective policy.")
	return nil
}

func importShodan(r *Report, data []byte) error {
	type banner struct {
		IP        string          `json:"ip_str"`
		Port      int             `json:"port"`
		Transport string          `json:"transport"`
		Product   string          `json:"product"`
		Vulns     json.RawMessage `json:"vulns"`
		Data      json.RawMessage `json:"data"`
		Matches   json.RawMessage `json:"matches"`
	}
	var consume func(banner) error
	consume = func(e banner) error {
		// Search API exports wrap banners in matches. Host exports wrap them in
		// data, while a service banner's data is a string that is never retained.
		for _, nested := range []json.RawMessage{e.Matches, e.Data} {
			if len(nested) > 0 && nested[0] == '[' {
				var entries []banner
				if err := json.Unmarshal(nested, &entries); err != nil {
					return fmt.Errorf("invalid nested banners")
				}
				for _, child := range entries {
					if child.IP == "" {
						child.IP = e.IP
					}
					if len(child.Matches) > 0 || len(child.Data) > 0 && child.Data[0] == '[' {
						return fmt.Errorf("unexpected recursive Shodan wrapper")
					}
					if err := consume(child); err != nil {
						return err
					}
				}
				return nil
			}
		}
		if net.ParseIP(e.IP) == nil || e.Port < 1 || e.Port > 65535 {
			return fmt.Errorf("banner needs ip_str and a port from 1 to 65535")
		}
		target := net.JoinHostPort(e.IP, strconv.Itoa(e.Port))
		r.observe("indexed service", target, e.Transport+" "+e.Product)
		r.edge(r.node("ip", e.IP), r.node("service", target), "indexed exposure")
		var names []string
		if len(e.Vulns) > 0 && string(e.Vulns) != "null" {
			if e.Vulns[0] == '[' {
				if err := json.Unmarshal(e.Vulns, &names); err != nil {
					return fmt.Errorf("invalid vulnerability identifiers")
				}
			} else {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(e.Vulns, &fields); err != nil {
					return fmt.Errorf("invalid vulnerability identifiers")
				}
				for name := range fields {
					names = append(names, name)
				}
			}
		}
		for _, name := range names {
			if strings.HasPrefix(name, "CVE-") {
				r.finding("info", name, target, "Shodan-indexed vulnerability candidate. The index can be stale; verify locally.")
			}
		}
		return nil
	}
	r.gap("Imported Shodan observations may be stale. No API key, live search or banner payload is used.")
	return jsonRecords(data, consume)
}

func importBBOT(r *Report, data []byte) error {
	type event struct {
		Type     string          `json:"type"`
		Data     json.RawMessage `json:"data"`
		Module   string          `json:"module"`
		Distance *int            `json:"scope_distance"`
	}
	return jsonRecords(data, func(e event) error {
		if e.Type == "" || len(e.Data) == 0 {
			return fmt.Errorf("event needs type and data")
		}
		if e.Distance != nil && *e.Distance > 0 {
			r.gap("Out-of-scope BBOT events were omitted.")
			return nil
		}
		switch e.Type {
		case "DNS_NAME", "IP_ADDRESS", "URL", "URL_UNVERIFIED", "OPEN_TCP_PORT", "STORAGE_BUCKET":
			var value string
			if e.Type == "STORAGE_BUCKET" {
				var bucket struct {
					URL string `json:"url"`
				}
				if err := json.Unmarshal(e.Data, &bucket); err != nil {
					return fmt.Errorf("invalid storage bucket")
				}
				value = bucket.URL
			} else if err := json.Unmarshal(e.Data, &value); err != nil {
				return fmt.Errorf("expected string event data")
			}
			r.observe(e.Type, value, "BBOT module: "+e.Module)
			id := r.node(strings.ToLower(e.Type), value)
			if u, err := url.Parse(value); err == nil && u.Hostname() != "" {
				r.edge(r.node("domain", u.Hostname()), id, "reported URL")
			}
		case "FINDING", "VULNERABILITY":
			var f struct {
				Host        string `json:"host"`
				Description string `json:"description"`
				Severity    string `json:"severity"`
			}
			if err := json.Unmarshal(e.Data, &f); err != nil {
				return fmt.Errorf("invalid finding event")
			}
			r.finding(f.Severity, f.Description, f.Host, "Imported BBOT event from "+e.Module+". Verify in the source report.")
		default:
			r.gap("Unsupported BBOT event types were omitted, including personal-profile and raw-secret records.")
		}
		return nil
	})
}

func importBloodHound(r *Report, data []byte) error {
	var doc struct {
		Meta struct {
			Type    string `json:"type"`
			Version int    `json:"version"`
		} `json:"meta"`
		Data []struct {
			ID         string `json:"ObjectIdentifier"`
			Properties struct {
				Name          string `json:"name"`
				Unconstrained bool   `json:"unconstraineddelegation"`
				Enabled       *bool  `json:"enabled"`
			} `json:"Properties"`
			Aces []struct {
				SID   string `json:"PrincipalSID"`
				Right string `json:"RightName"`
				Type  string `json:"PrincipalType"`
			} `json:"Aces"`
			Members []struct {
				ID   string `json:"ObjectIdentifier"`
				Type string `json:"ObjectType"`
			} `json:"Members"`
		} `json:"data"`
	}
	if err := decodeJSON(data, &doc); err != nil {
		return err
	}
	if doc.Data == nil || doc.Meta.Type == "" || doc.Meta.Version < 5 || doc.Meta.Version > 6 {
		return fmt.Errorf("expected a BloodHound v5/v6 collection JSON with data and meta")
	}
	names := make(map[string]string)
	for _, entry := range doc.Data {
		if entry.ID == "" {
			return fmt.Errorf("object identifier missing")
		}
		name := entry.Properties.Name
		if name == "" {
			name = entry.ID
		}
		names[entry.ID] = name
	}
	for _, entry := range doc.Data {
		name := names[entry.ID]
		// SID-based identifiers preserve distinct objects with the same display name.
		id := r.node("directory object", entry.ID)
		r.observe("directory name", entry.ID, name)
		for _, ace := range entry.Aces {
			if ace.SID == "" || ace.Right == "" {
				continue
			}
			r.edge(r.node("directory object", ace.SID), id, ace.Right)
			switch ace.Right {
			case "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "AddMember", "ForceChangePassword", "AddKeyCredentialLink":
				r.finding("medium", "Sensitive directory permission: "+ace.Right, name, "Principal "+ace.SID+" holds this reported right. Context and effective permission require directory review.")
			}
		}
		for _, member := range entry.Members {
			if member.ID != "" {
				r.edge(r.node("directory object", member.ID), id, "MemberOf")
			}
		}
		if entry.Properties.Unconstrained && (entry.Properties.Enabled == nil || *entry.Properties.Enabled) {
			r.finding("high", "Unconstrained delegation reported", name, "Review whether this enabled directory object needs unconstrained delegation.")
		}
		if len(r.Nodes) >= maxRecords || len(r.Edges) >= maxRecords {
			r.limit()
			break
		}
	}
	r.gap("Collection JSON only, not ZIP or OpenGraph. ACL and membership review is not BloodHound pathfinding or proof of an exploitable attack path.")
	return nil
}

func importTShark(r *Report, data []byte) error {
	type packet struct {
		Source struct {
			Layers map[string]json.RawMessage `json:"layers"`
		} `json:"_source"`
	}
	return jsonRecords(data, func(p packet) error {
		if p.Source.Layers == nil {
			return fmt.Errorf("expected TShark -T json records")
		}
		get := func(layer, field string) string {
			var values map[string]json.RawMessage
			if json.Unmarshal(p.Source.Layers[layer], &values) != nil {
				return ""
			}
			var value string
			if json.Unmarshal(values[field], &value) == nil {
				return value
			}
			return ""
		}
		src, dst := get("ip", "ip.src"), get("ip", "ip.dst")
		if src == "" {
			src, dst = get("ipv6", "ipv6.src"), get("ipv6", "ipv6.dst")
		}
		if src == "" || dst == "" {
			r.gap("Packets without IPv4/IPv6 metadata were omitted.")
			return nil
		}
		if net.ParseIP(src) == nil || net.ParseIP(dst) == nil {
			return fmt.Errorf("invalid IP metadata")
		}
		protocol := get("frame", "frame.protocols")
		r.observe("packet", src+" → "+dst, protocol)
		r.edge(r.node("ip", src), r.node("ip", dst), "observed traffic")
		return nil
	})
}
