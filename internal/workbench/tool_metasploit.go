// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type metasploitService struct {
	ID    string `xml:"id"`
	Port  int    `xml:"port"`
	Proto string `xml:"proto"`
	Name  string `xml:"name"`
	State string `xml:"state"`
}

type metasploitVulnerability struct {
	Name      string `xml:"name"`
	ServiceID string `xml:"service-id"`
	Refs      []struct {
		Value string `xml:",chardata"`
		Name  string `xml:"name"`
	} `xml:"refs>ref"`
}

// auditMetasploit preserves imported assertions without promoting them to
// verified exploitability. Source info, loot, credentials and sessions are ignored.
func auditMetasploit(ctx context.Context, req ToolRequest) (*Report, error) {
	if req.RunEngine {
		return nil, fmt.Errorf("Metasploit engine execution is not supported; import a MetasploitV5 assessment report")
	}
	if req.Target != "" {
		return nil, fmt.Errorf("Metasploit assessment accepts report input only; live targets are not executed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	if err := checkInput(data); err != nil {
		return nil, err
	}
	var doc struct {
		XMLName xml.Name `xml:"MetasploitV5"`
		Hosts   []struct {
			Address  string                    `xml:"address"`
			Services []metasploitService       `xml:"services>service"`
			Vulns    []metasploitVulnerability `xml:"vulns>vuln"`
		} `xml:"hosts>host"`
	}
	if err := decodeXML(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Hosts) == 0 {
		return nil, fmt.Errorf("MetasploitV5 report contains no hosts")
	}
	r := newReport("metasploit", "Metasploit imported vulnerability evidence reviewed.", data)
	r.gap("Imported host, service and reference assertions are not independently verified. No exploit checks, payloads, sessions, credentials or live network operations run.")
	records, reviewed, correlated := 0, 0, 0
	for _, host := range doc.Hosts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if records >= maxRecords {
			r.limit()
			break
		}
		records++
		ip := net.ParseIP(strings.TrimSpace(host.Address))
		if ip == nil {
			return nil, fmt.Errorf("Metasploit host requires a valid IP address")
		}
		address := ip.String()
		hostNode := r.node("ip", address)
		r.observe("import provenance", address, "Host address recorded in supplied MetasploitV5 report; not independently verified.")
		services := make(map[string]string)
		for _, service := range host.Services {
			if records >= maxRecords {
				r.limit()
				break
			}
			records++
			proto := strings.ToLower(strings.TrimSpace(service.Proto))
			if service.Port < 1 || service.Port > 65535 || (proto != "tcp" && proto != "udp") {
				return nil, fmt.Errorf("Metasploit service requires a valid port and tcp or udp protocol")
			}
			target := proto + "://" + net.JoinHostPort(address, strconv.Itoa(service.Port))
			id := strings.TrimSpace(service.ID)
			if id != "" {
				if _, exists := services[id]; exists {
					return nil, fmt.Errorf("Metasploit host contains duplicate service IDs")
				}
				services[id] = target
			}
			state := strings.ToLower(strings.TrimSpace(service.State))
			if state != "open" && state != "closed" && state != "filtered" && state != "unknown" && state != "" {
				state = "unrecognized"
			}
			// Service names are untrusted report text; retain only conventional tokens.
			name := strings.TrimSpace(service.Name)
			if !regexp.MustCompile(`^[A-Za-z0-9_.+/-]{0,64}$`).MatchString(name) {
				name = "omitted"
			}
			r.observe("imported service", target, "name="+name+" state="+state+"; source assertion, not a live observation")
			r.edge(hostNode, r.node("service", target), "reported service")
		}
		for _, vuln := range host.Vulns {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if records >= maxRecords {
				r.limit()
				break
			}
			records++
			if strings.TrimSpace(vuln.Name) == "" {
				return nil, fmt.Errorf("Metasploit vulnerability is missing a name")
			}
			target := address
			serviceID := strings.TrimSpace(vuln.ServiceID)
			serviceMatched := false
			if serviceID != "" {
				if serviceTarget, exists := services[serviceID]; exists {
					target, serviceMatched = serviceTarget, true
					correlated++
				} else {
					r.gap("A vulnerability references a missing service ID in its host; it remains host-level and requires source-report review.")
				}
			}
			// A supplied name may contain arbitrary evidence or credentials. A digest
			// identifies the original record without copying its free-form contents.
			recordID := digest([]byte(address + "\x00" + vuln.Name + "\x00" + serviceID))[:16]
			vulnNode := r.node("imported vulnerability", target+"/record/"+recordID)
			parentNode := hostNode
			if serviceMatched {
				parentNode = r.node("service", target)
			}
			r.edge(parentNode, vulnNode, "reported vulnerability candidate")
			references := make(map[string]bool)
			for _, ref := range vuln.Refs {
				if len(references) >= 32 {
					r.Limited = true
					r.gap("Vulnerability reference collection is limited to 32 distinct references per record.")
					break
				}
				value := strings.TrimSpace(ref.Name)
				if value == "" {
					value = strings.TrimSpace(ref.Value)
				}
				normalized, ok := metasploitReference(value)
				if !ok {
					r.gap("Unsupported or malformed vulnerability references were omitted; no identifiers were inferred.")
					continue
				}
				if references[normalized] {
					continue
				}
				references[normalized] = true
				r.edge(vulnNode, r.node("advisory reference", normalized), "cites imported reference")
				r.observe("imported advisory reference", target, normalized)
			}
			detail := "Imported record " + recordID + ". Unverified vulnerability candidate; consult the original report for evidence. "
			if serviceMatched {
				detail += "Service association matched the supplied host-local service ID. "
			} else {
				detail += "No verified service association. "
			}
			if len(references) > 0 {
				detail += "Review cited advisories against installed product/version, apply vendor fixes, and restrict affected exposure where needed."
			} else {
				detail += "No supported advisory references supplied; establish product/version and vendor guidance before prioritizing a patch."
			}
			r.finding("info", "Imported vulnerability requires validation", target, detail)
			reviewed++
		}
	}
	r.Summary = fmt.Sprintf("Reviewed %d imported vulnerability candidates; %d matched host-local service IDs; exploitability remains unverified.", reviewed, correlated)
	return r, nil
}

func metasploitReference(value string) (string, bool) {
	upper := strings.ToUpper(value)
	if regexp.MustCompile(`^CVE[-:]\d{4}-\d{4,19}$`).MatchString(upper) {
		return strings.Replace(upper, "CVE:", "CVE-", 1), true
	}
	if regexp.MustCompile(`^(BID|OSVDB|EDB|MSB|US-CERT-VU)-[A-Za-z0-9.-]{1,64}$`).MatchString(value) {
		return value, true
	}
	if strings.HasPrefix(value, "URL-") {
		value = strings.TrimPrefix(value, "URL-")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || len(value) > 512 {
		return "", false
	}
	// References do not need query tokens, fragments or embedded user credentials.
	parsed.RawQuery, parsed.Fragment, parsed.RawFragment = "", "", ""
	return parsed.String(), true
}
