// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Go's XML decoder does not resolve external entities or fetch DTDs.
func decodeXML(data []byte, value any) error {
	d := xml.NewDecoder(bytes.NewReader(data))
	if err := d.Decode(value); err != nil {
		return fmt.Errorf("malformed XML or unexpected root element")
	}
	for {
		token, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("malformed trailing XML")
		}
		switch t := token.(type) {
		case xml.StartElement:
			return fmt.Errorf("expected one XML document")
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return fmt.Errorf("unexpected trailing XML text")
			}
		}
	}
}

func importNmap(r *Report, data []byte) error {
	var doc struct {
		XMLName xml.Name `xml:"nmaprun"`
		Hosts   []struct {
			Addresses []struct {
				Addr string `xml:"addr,attr"`
				Type string `xml:"addrtype,attr"`
			} `xml:"address"`
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				Number   int    `xml:"portid,attr"`
				State    struct {
					Value string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
				} `xml:"service"`
			} `xml:"ports>port"`
		} `xml:"host"`
		Finished struct {
			Exit string `xml:"exit,attr"`
		} `xml:"runstats>finished"`
	}
	if err := decodeXML(data, &doc); err != nil {
		return err
	}
	for _, host := range doc.Hosts {
		address := ""
		for _, a := range host.Addresses {
			if net.ParseIP(a.Addr) != nil {
				address = a.Addr
				break
			}
		}
		if address == "" {
			r.gap("A host with no valid IP address was omitted.")
			continue
		}
		n := r.node("ip", address)
		for _, p := range host.Ports {
			if p.State.Value != "open" {
				continue
			}
			if p.Number < 1 || p.Number > 65535 || p.Protocol != "tcp" && p.Protocol != "udp" {
				return fmt.Errorf("invalid port record")
			}
			target := net.JoinHostPort(address, strconv.Itoa(p.Number))
			r.observe(p.Protocol+" service", target, strings.Join([]string{p.Service.Name, p.Service.Product, p.Service.Version}, " "))
			r.edge(n, r.node("service", target), "exposes "+p.Protocol)
		}
	}
	if doc.Finished.Exit != "success" {
		r.gap("The source report does not declare a successful completed Nmap run.")
	}
	r.gap("Open ports describe exposure; they are not automatically vulnerabilities. NSE script output is omitted.")
	return nil
}

func importBurp(r *Report, data []byte) error {
	var doc struct {
		XMLName xml.Name `xml:"issues"`
		Issues  []struct {
			Name       string `xml:"name"`
			Host       string `xml:"host"`
			Path       string `xml:"path"`
			Severity   string `xml:"severity"`
			Confidence string `xml:"confidence"`
		} `xml:"issue"`
	}
	if err := decodeXML(data, &doc); err != nil {
		return err
	}
	for _, issue := range doc.Issues {
		if issue.Name == "" || issue.Host == "" {
			return fmt.Errorf("issue is missing name or host")
		}
		r.finding(issue.Severity, issue.Name, issue.Host+issue.Path, "Imported Burp issue; confidence: "+issue.Confidence+". Review evidence in the original project.")
		r.node("url", issue.Host+issue.Path)
	}
	return nil
}

func importMetasploit(r *Report, data []byte) error {
	var doc struct {
		XMLName xml.Name `xml:"MetasploitV5"`
		Hosts   []struct {
			Address  string `xml:"address"`
			Services []struct {
				Port  int    `xml:"port"`
				Proto string `xml:"proto"`
				Name  string `xml:"name"`
				State string `xml:"state"`
			} `xml:"services>service"`
			Vulns []struct {
				Name string `xml:"name"`
			} `xml:"vulns>vuln"`
		} `xml:"hosts>host"`
	}
	if err := decodeXML(data, &doc); err != nil {
		return err
	}
	for _, h := range doc.Hosts {
		if net.ParseIP(h.Address) == nil {
			return fmt.Errorf("host is missing a valid address")
		}
		n := r.node("ip", h.Address)
		for _, s := range h.Services {
			if s.Port < 1 || s.Port > 65535 {
				return fmt.Errorf("invalid service port")
			}
			target := net.JoinHostPort(h.Address, strconv.Itoa(s.Port))
			r.observe("service", target, s.Proto+" "+s.Name+" "+s.State)
			r.edge(n, r.node("service", target), "reported service")
		}
		for _, v := range h.Vulns {
			r.finding("info", v.Name, h.Address, "Imported vulnerability label; severity and exploitability have not been verified.")
		}
	}
	r.gap("MetasploitV5 host, service and vulnerability labels only. Credentials, sessions, loot and exploit execution are excluded.")
	return nil
}
