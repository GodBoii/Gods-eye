// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"strings"
)

func columnName(value string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "-", "", "_", "", "\ufeff", "").Replace(strings.TrimSpace(value)))
}

func importCSV(r *Report, format string, data []byte) error {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1
	var headers []string
	rows := 0
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("malformed CSV record")
		}
		if len(row) == 0 {
			continue
		}
		if format == "aircrack" && columnName(row[0]) == "stationmac" {
			break
		}
		if headers == nil {
			for _, h := range row {
				headers = append(headers, columnName(h))
			}
			getHeader := func(name string) bool {
				for _, h := range headers {
					if h == name {
						return true
					}
				}
				return false
			}
			valid := false
			switch format {
			case "aircrack":
				valid = getHeader("bssid") && getHeader("privacy") && getHeader("essid")
			case "cloudfox":
				valid = getHeader("arn") || getHeader("endpoint") || getHeader("name") || getHeader("resource")
			case "spiderfoot":
				valid = getHeader("type") && getHeader("data")
			case "recon-ng":
				valid = getHeader("host") || getHeader("ipaddress")
			case "sqlmap":
				valid = getHeader("targeturl") && getHeader("parameter") && getHeader("technique(s)")
			}
			if !valid {
				return fmt.Errorf("unsupported column headers for %s", format)
			}
			continue
		}
		if len(row) != len(headers) {
			return fmt.Errorf("CSV row has %d fields, expected %d", len(row), len(headers))
		}
		get := func(names ...string) string {
			for _, name := range names {
				for i, h := range headers {
					if h == name && strings.TrimSpace(row[i]) != "" {
						return strings.TrimSpace(row[i])
					}
				}
			}
			return ""
		}
		rows++
		if rows > maxRecords {
			r.limit()
			break
		}
		switch format {
		case "aircrack":
			bssid, privacy := get("bssid"), strings.ToUpper(get("privacy"))
			if _, err := net.ParseMAC(bssid); err != nil {
				return fmt.Errorf("invalid access point BSSID")
			}
			r.observe("wireless access point", bssid, fmt.Sprintf("ESSID %s · channel %s · %s · %s", get("essid"), get("channel"), privacy, get("authentication")))
			r.node("access point", bssid)
			if privacy == "OPN" || privacy == "WEP" {
				r.finding("high", "Weak wireless protection: "+privacy, bssid, "Review the recorded access point configuration and use current WPA2/WPA3 settings where supported.")
			}
		case "cloudfox":
			target := get("arn", "endpoint", "resource", "name")
			if target == "" {
				return fmt.Errorf("cloud row has no resource identifier")
			}
			r.observe("cloud resource", target, "Service "+get("service", "type")+" · region "+get("region"))
			n := r.node("cloud resource", target)
			if account := get("account", "accountid"); account != "" {
				r.edge(r.node("cloud account", account), n, "contains")
			}
			if strings.EqualFold(get("public"), "true") || strings.EqualFold(get("public"), "yes") {
				r.finding("medium", "Resource reported as public", target, "Imported CloudFox public flag. Verify provider policy and intended exposure.")
			}
		case "spiderfoot":
			if get("f/p") == "1" {
				r.gap("SpiderFoot events marked false positive were omitted.")
				continue
			}
			kind, value := get("type"), get("data")
			switch kind {
			case "INTERNET_NAME", "IP_ADDRESS", "IPV6_ADDRESS", "DOMAIN_NAME", "LINKED_URL_INTERNAL", "TCP_PORT_OPEN":
				r.observe(kind, value, "SpiderFoot module: "+get("module"))
				r.node(strings.ToLower(kind), value)
			default:
				r.gap("Unsupported SpiderFoot event types were omitted.")
			}
		case "recon-ng":
			host, ip := get("host"), get("ipaddress")
			if host == "" && ip == "" {
				continue
			}
			r.observe("host", host, ip)
			if host != "" && net.ParseIP(ip) != nil {
				r.edge(r.node("domain", host), r.node("ip", ip), "reported address")
			} else {
				r.node("host", get("host", "ipaddress"))
			}
		case "sqlmap":
			if get("targeturl") == "" {
				return fmt.Errorf("missing target URL")
			}
			if get("parameter") == "" || get("technique(s)") == "" {
				r.observe("assessment result", get("targeturl"), "No injection technique recorded in this row")
				continue
			}
			r.finding("high", "Reported SQL injection", get("targeturl"), "Parameter "+get("parameter")+" · place "+get("place")+" · technique "+get("technique(s)")+". Verify in the source assessment; no requests were replayed.")
		}
	}
	if headers == nil {
		return fmt.Errorf("missing CSV header")
	}
	if format == "aircrack" {
		r.gap("Access-point metadata only. Client stations, packet capture, deauthentication, handshake collection and password cracking are excluded.")
	}
	return nil
}
