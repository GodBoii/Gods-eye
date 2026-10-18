// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const airgorahHeader = "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"

func airgorahRow(mac, privacy, cipher, ssid string, channel int) string {
	return fmt.Sprintf("%s, 2026-10-18, 2026-10-18, %d, 54, %s, %s, PSK, -40, 20, 0, 0.0.0.0, 4, %s, SECRET_KEY\n", mac, channel, privacy, cipher, ssid)
}

func airgorahRequest(t *testing.T, before, after string) ToolRequest {
	t.Helper()
	data, err := json.Marshal(map[string]string{"before": before, "after": after})
	if err != nil {
		t.Fatal(err)
	}
	return ToolRequest{Tool: "airgorah", Input: string(data)}
}

func TestAirgorahSnapshotChanges(t *testing.T) {
	before := airgorahHeader + airgorahRow("02:00:00:00:00:01", "WPA2", "CCMP", "Office", 1)
	after := airgorahHeader + airgorahRow("02:00:00:00:00:01", "WPA", "TKIP", "NewOffice", 6) + airgorahRow("02:00:00:00:00:02", "OPN", "", "Guest", 11)
	after += "\nStation MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n12:34:56:78:90:ab, station-secret, data\n"
	r, err := auditAirgorah(context.Background(), airgorahRequest(t, before, after))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 3 {
		t.Fatalf("expected downgrade, cipher and new-open findings: %+v", r.Findings)
	}
	kinds := map[string]bool{}
	for _, o := range r.Observations {
		kinds[o.Kind] = true
	}
	if !kinds["SSID changed"] || !kinds["channel changed"] {
		t.Fatal("missing metadata change observations")
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET_KEY", "station-secret", "12:34:56:78:90:ab"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("report leaked %s", secret)
		}
	}
}

func TestAirgorahLegitimateSharedSSID(t *testing.T) {
	csv := airgorahHeader + airgorahRow("02:00:00:00:00:01", "WPA2", "CCMP", "Office", 1) + airgorahRow("02:00:00:00:00:02", "WPA2", "CCMP", "Office", 6)
	r, err := auditAirgorah(context.Background(), airgorahRequest(t, csv, csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("legitimate multiple APs produced findings: %+v", r.Findings)
	}
	found := false
	for _, o := range r.Observations {
		if o.Kind == "shared SSID" && strings.Contains(o.Value, "not proof") {
			found = true
		}
	}
	if !found {
		t.Fatal("shared SSID observation missing")
	}
}

func TestAirgorahRejectInvalidInput(t *testing.T) {
	valid := airgorahHeader + airgorahRow("02:00:00:00:00:01", "WPA2", "CCMP", "Office", 1)
	for name, input := range map[string]string{"bad MAC": airgorahHeader + airgorahRow("invalid", "WPA2", "CCMP", "Office", 1), "bad CSV": airgorahHeader + "\"unterminated", "bad header": "BSSID,ESSID\n", "truncated": airgorahHeader + "02:00:00:00:00:01, test\n", "bad channel": airgorahHeader + airgorahRow("02:00:00:00:00:01", "WPA2", "CCMP", "Office", 234)} {
		t.Run(name, func(t *testing.T) {
			if _, err := auditAirgorah(context.Background(), airgorahRequest(t, valid, input)); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	for _, req := range []ToolRequest{{Input: `{"before":"x","after":"x","unknown":1}`}, {Input: `{} {}`}, {Input: valid, RunEngine: true}, {Input: valid, Target: "example.com"}, {Input: strings.Repeat("x", MaxInput+1)}} {
		if _, err := auditAirgorah(context.Background(), req); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditAirgorah(ctx, airgorahRequest(t, valid, valid)); err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestAirgorahBoundsAndAmbiguousEvidence(t *testing.T) {
	var snapshot strings.Builder
	snapshot.WriteString(airgorahHeader)
	for i := 0; i < 1001; i++ {
		snapshot.WriteString(airgorahRow(fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256), "WPA2", "CCMP", "Office", 1))
	}
	r, err := auditAirgorah(context.Background(), airgorahRequest(t, airgorahHeader, snapshot.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Limited {
		t.Fatal("record cap not surfaced")
	}
	conflict := airgorahHeader + airgorahRow("02:00:00:00:00:01", "WPA2", "CCMP", "Office", 1) + airgorahRow("02:00:00:00:00:01", "OPN", "", "Office", 1)
	r, err = auditAirgorah(context.Background(), airgorahRequest(t, airgorahHeader, conflict))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Limited || len(r.Findings) != 0 {
		t.Fatal("conflicting records were treated as reliable")
	}
}

func TestAirgorahQuotedSSIDAndUnknownProtection(t *testing.T) {
	before := airgorahHeader + airgorahRow("02:00:00:00:00:01", "UNKNOWN", "CCMP", "\"Office, west\"", 1)
	after := airgorahHeader + airgorahRow("02:00:00:00:00:01", "OPN", "", "\"Office, west\"", 1)
	r, err := auditAirgorah(context.Background(), airgorahRequest(t, before, after))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatal("unknown protection ranked as a confirmed downgrade")
	}
	if !strings.Contains(r.Observations[0].Value, "Office, west") {
		t.Fatal("quoted SSID was not parsed")
	}
}

func TestAirgorahSSIDControlsSanitized(t *testing.T) {
	csv := airgorahHeader + airgorahRow("02:00:00:00:00:01", "WPA2", "CCMP", "Office\x1b[31m", 1)
	r, err := auditAirgorah(context.Background(), airgorahRequest(t, csv, csv))
	if err != nil {
		t.Fatal(err)
	}
	for _, observation := range r.Observations {
		if strings.ContainsRune(observation.Value, '\x1b') {
			t.Fatal("SSID control character retained")
		}
	}
}
