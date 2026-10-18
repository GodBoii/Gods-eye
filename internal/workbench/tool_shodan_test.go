// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestAuditShodanHostEvidence(t *testing.T) {
	input := `{"ip_str":"192.0.2.1","data":[{"port":21,"product":"vsftpd","version":"3.0.3","timestamp":"2024-01-01T12:00:00.123456","ftp":{"anonymous":true},"data":"password=secret-banner","vulns":{"CVE-2024-12345":{"verified":true,"summary":"secret-summary"},"CVE-2024-12346":{"verified":false}},"ssl":{"cert":{"expires":"20230101000000Z"}}}]}`
	r, err := auditShodan(context.Background(), ToolRequest{Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 4 {
		t.Fatalf("findings: %+v", r.Findings)
	}
	if r.Findings[0].Severity != "medium" || !strings.Contains(r.Findings[0].Title, "reported verified") || r.Findings[1].Severity != "info" {
		t.Fatalf("verification classification: %+v", r.Findings)
	}
	if !strings.Contains(r.Observations[0].Value, "vsftpd") || !strings.Contains(r.Observations[0].Value, "3.0.3") || !strings.Contains(r.Observations[0].Value, "stale") {
		t.Fatal(r.Observations)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-banner") || strings.Contains(string(encoded), "secret-summary") {
		t.Fatal("retained raw banner")
	}
}

func TestAuditShodanScopeAndNoPortInference(t *testing.T) {
	input := `{"total":3,"matches":[{"ip_str":"192.0.2.1","port":6379,"product":"Redis","timestamp":"2024-01-01T00:00:00Z"},{"ip_str":"192.0.2.2","port":445,"smb":{"anonymous":true},"vulns":{"CVE-2024-12345":{"verified":true}}}]}`
	r, err := auditShodan(context.Background(), ToolRequest{Input: input, Target: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 || len(r.Observations) != 1 || !r.Limited {
		t.Fatalf("scope/port inference: %+v", r)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "192.0.2.2") || strings.Contains(string(encoded), "CVE-2024") {
		t.Fatal("out of scope evidence retained")
	}
}

func TestAuditShodanFormats(t *testing.T) {
	for _, input := range []string{
		`[{"ip_str":"2001:db8::1","port":443,"transport":"udp","vulns":["CVE-2020-1234"]}]`,
		"{\"ip_str\":\"192.0.2.1\",\"port\":22}\n{\"ip_str\":\"192.0.2.2\",\"port\":445,\"smb\":{\"anonymous\":false}}",
	} {
		r, err := auditShodan(context.Background(), ToolRequest{Input: input})
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Observations) == 0 {
			t.Fatal("no observations")
		}
		for _, f := range r.Findings {
			if f.Severity != "info" {
				t.Fatalf("unverified CVE promoted: %+v", f)
			}
		}
	}
}

func TestAuditShodanRejectsMalformedAndExecution(t *testing.T) {
	for _, req := range []ToolRequest{
		{RunEngine: true}, {Target: "example.com"}, {Input: "   "}, {Input: "null"},
		{Input: `{"ip_str":"192.0.2.1","port":0}`},
		{Input: `{"ip_str":"192.0.2.1","port":22,"transport":"raw"}`},
		{Input: `{"ip_str":"192.0.2.1","port":22,"vulns":{"CVE-2020-1234":{"verified":"true"}}}`},
		{Input: `{"ip_str":"192.0.2.1","port":22,"vulns":["CVE-secret"]}`},
		{Input: `[{"ip_str":"192.0.2.1","port":22}] {}`},
		{Input: `{"matches":[{"matches":[]}]}`},
	} {
		if _, err := auditShodan(context.Background(), req); err == nil {
			t.Fatalf("accepted malformed request: %+v", req)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditShodan(ctx, ToolRequest{Input: `{"ip_str":"192.0.2.1","port":22}`}); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestAuditShodanBounds(t *testing.T) {
	var input strings.Builder
	input.WriteByte('[')
	for i := 0; i < 10010; i++ {
		if i > 0 {
			input.WriteByte(',')
		}
		fmt.Fprintf(&input, `{"ip_str":"192.0.2.1","port":%d}`, i%65535+1)
	}
	input.WriteByte(']')
	r, err := auditShodan(context.Background(), ToolRequest{Input: input.String()})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Limited || len(r.Observations)+len(r.Findings) > 1000 || !strings.Contains(strings.Join(r.Gaps, " "), "10,000") {
		t.Fatalf("unbounded result: obs=%d findings=%d gaps=%v", len(r.Observations), len(r.Findings), r.Gaps)
	}
}
