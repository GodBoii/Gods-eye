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
	"sort"
	"strconv"
	"strings"
	"time"
)

type airgorahAP struct {
	ssid, privacy, cipher, authentication string
	channel                               int
}

// auditAirgorah compares supplied AP snapshots without operating a radio.
func auditAirgorah(ctx context.Context, req ToolRequest) (*Report, error) {
	if req.RunEngine || req.Target != "" {
		return nil, fmt.Errorf("wireless change review accepts offline snapshot JSON only")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
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
	var input struct {
		Before string `json:"before"`
		After  string `json:"after"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil {
		return nil, fmt.Errorf("invalid snapshot JSON")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("provide exactly one snapshot JSON object")
	}
	if input.Before == "" || input.After == "" {
		return nil, fmt.Errorf("provide before and after AP CSV snapshots")
	}
	r := newReport("airgorah", "Offline wireless snapshot comparison.", data)
	before, err := airgorahSnapshot(ctx, input.Before, r, "before")
	if err != nil {
		return nil, err
	}
	after, err := airgorahSnapshot(ctx, input.After, r, "after")
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(after))
	for key := range after {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ssids := map[string][]string{}
	for _, bssid := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ap := after[bssid]
		if ap.ssid != "" {
			ssids[ap.ssid] = append(ssids[ap.ssid], bssid)
		}
		r.observe("wireless access point", bssid, fmt.Sprintf("SSID %q · channel %d · %s · %s · %s", ap.ssid, ap.channel, ap.privacy, ap.cipher, ap.authentication))
		old, exists := before[bssid]
		if !exists {
			r.observe("newly observed access point", bssid, "Not present in the supplied before snapshot; this does not establish when it was deployed.")
			if airgorahSecurity(ap.privacy) == 0 {
				r.finding("medium", "Newly observed open access point", bssid, "The after snapshot advertises OPN protection. Confirm the intended network configuration; this does not prove network access.")
			}
			continue
		}
		if ap.ssid != old.ssid {
			r.observe("SSID changed", bssid, fmt.Sprintf("%q → %q", old.ssid, ap.ssid))
		}
		if ap.channel != old.channel {
			r.observe("channel changed", bssid, fmt.Sprintf("%d → %d; channel changes can be normal radio management.", old.channel, ap.channel))
		}
		oldRank, rank := airgorahSecurity(old.privacy), airgorahSecurity(ap.privacy)
		if oldRank >= 0 && rank >= 0 && rank < oldRank {
			r.finding("high", "Wireless protection downgrade advertised", bssid, fmt.Sprintf("Protection changed from %s to %s. Verify the controller configuration; exported advertisements do not prove exploitability.", old.privacy, ap.privacy))
		}
		if strings.Contains(old.cipher, "CCMP") && !strings.Contains(ap.cipher, "CCMP") && strings.Contains(ap.cipher, "TKIP") {
			r.finding("medium", "Legacy cipher replaces CCMP", bssid, "The after snapshot advertises TKIP without the previously advertised CCMP cipher. Verify the AP configuration.")
		}
		if old.privacy != ap.privacy || old.cipher != ap.cipher || old.authentication != ap.authentication {
			r.observe("protection changed", bssid, fmt.Sprintf("%s/%s/%s → %s/%s/%s", old.privacy, old.cipher, old.authentication, ap.privacy, ap.cipher, ap.authentication))
		}
	}
	ssidKeys := make([]string, 0, len(ssids))
	for ssid := range ssids {
		ssidKeys = append(ssidKeys, ssid)
	}
	sort.Strings(ssidKeys)
	for _, ssid := range ssidKeys {
		if len(ssids[ssid]) > 1 {
			r.observe("shared SSID", "", fmt.Sprintf("SSID %q appears on %d BSSIDs. Multiple APs, mesh and band steering are legitimate explanations; this is not proof of an evil twin.", ssid, len(ssids[ssid])))
		}
	}
	missing := 0
	for key := range before {
		if _, ok := after[key]; !ok {
			missing++
		}
	}
	r.observe("snapshot coverage", "", fmt.Sprintf("%d before APs · %d after APs · %d before APs absent from after; absence can reflect collection coverage.", len(before), len(after), missing))
	r.gap("Snapshots have no verified collector coverage, ordering or authenticity. Missing APs do not prove removal. Hidden SSIDs and same-SSID APs do not establish identity or impersonation. No active wireless testing or vulnerability proof.")
	r.gap("Only BSSID, sanitized SSID, channel and advertised protection metadata are retained. Station identities, probes, packet contents and key columns are omitted. Unknown protection values are not ranked.")
	r.Summary = fmt.Sprintf("Compared %d before and %d after access points; %d configuration review findings.", len(before), len(after), len(r.Findings))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

func airgorahSecurity(s string) int {
	// Transition modes use their weakest advertised generation.
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return -1
	}
	rank := 99
	for _, field := range fields {
		v := -1
		switch field {
		case "OPN":
			v = 0
		case "WEP":
			v = 1
		case "WPA":
			v = 2
		case "WPA2":
			v = 3
		case "WPA3":
			v = 4
		}
		if v < 0 {
			return -1
		}
		if v < rank {
			rank = v
		}
	}
	return rank
}

func airgorahSnapshot(ctx context.Context, input string, r *Report, label string) (map[string]airgorahAP, error) {
	reader := csv.NewReader(strings.NewReader(input))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	aps := map[string]airgorahAP{}
	ambiguous := map[string]bool{}
	var columns map[string]int
	rows := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s snapshot contains malformed CSV", label)
		}
		if len(record) == 0 {
			continue
		}
		first := strings.TrimSpace(record[0])
		if first == "Station MAC" {
			break
		} // Station records are never retained.
		if columns == nil {
			if first != "BSSID" {
				return nil, fmt.Errorf("%s snapshot requires an Airodump-ng AP CSV header", label)
			}
			columns = map[string]int{}
			for i, field := range record {
				name := strings.TrimSpace(field)
				if _, exists := columns[name]; exists && name != "" {
					return nil, fmt.Errorf("%s snapshot has duplicate columns", label)
				}
				columns[name] = i
			}
			for _, name := range []string{"BSSID", "channel", "Privacy", "Cipher", "Authentication", "ESSID"} {
				if _, ok := columns[name]; !ok {
					return nil, fmt.Errorf("%s snapshot is missing required AP columns", label)
				}
			}
			continue
		}
		rows++
		if rows > maxRecords {
			r.Limited = true
			r.gap("An AP snapshot exceeded 1,000 records; later rows were omitted and comparisons are incomplete.")
			break
		}
		get := func(name string) string {
			i := columns[name]
			if i >= len(record) {
				return ""
			}
			return strings.TrimSpace(record[i])
		}
		for _, index := range columns {
			if index >= len(record) {
				return nil, fmt.Errorf("%s snapshot contains a truncated AP row", label)
			}
		}
		mac, err := net.ParseMAC(get("BSSID"))
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || bytes.Equal(mac, make([]byte, 6)) {
			return nil, fmt.Errorf("%s snapshot contains an invalid AP BSSID", label)
		}
		channel, err := strconv.Atoi(get("channel"))
		if err != nil || channel < -1 || channel > 233 {
			return nil, fmt.Errorf("%s snapshot contains an invalid channel", label)
		}
		ap := airgorahAP{text(get("ESSID")), strings.ToUpper(text(get("Privacy"))), strings.ToUpper(text(get("Cipher"))), strings.ToUpper(text(get("Authentication"))), channel}
		key := mac.String()
		if ambiguous[key] {
			continue
		}
		if old, exists := aps[key]; exists && old != ap {
			delete(aps, key)
			ambiguous[key] = true
			r.Limited = true
			r.gap("Conflicting duplicate BSSID records were omitted from a snapshot; their changes cannot be assessed.")
			continue
		}
		aps[key] = ap
	}
	if columns == nil {
		return nil, fmt.Errorf("%s snapshot has no AP CSV header", label)
	}
	return aps, nil
}
