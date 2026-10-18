// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func bloodHoundRequest(t *testing.T, start, end string, collections ...string) ToolRequest {
	t.Helper()
	values := make([]json.RawMessage, len(collections))
	for index, collection := range collections {
		values[index] = json.RawMessage(collection)
	}
	data, err := json.Marshal(map[string]any{"collections": values, "start": start, "end": end})
	if err != nil {
		t.Fatal(err)
	}
	return ToolRequest{Input: string(data)}
}

const bloodHoundUsers = `{"meta":{"type":"users","version":6},"data":[{"ObjectIdentifier":"S-1-5-21-1","Properties":{"name":"same-name","enabled":true,"password":"PRIVATE_SECRET"}},{"ObjectIdentifier":"S-1-5-21-2","Properties":{"name":"same-name","enabled":true}}]}`
const bloodHoundGroup = `{"meta":{"type":"groups","version":5},"data":[{"ObjectIdentifier":"S-1-5-21-3","Members":[{"ObjectIdentifier":"S-1-5-21-1"}]}]}`
const bloodHoundTarget = `{"meta":{"type":"computers","version":6},"data":[{"ObjectIdentifier":"S-1-5-21-4","Properties":{"enabled":true},"Aces":[{"PrincipalSID":"S-1-5-21-3","RightName":"GenericAll"}]}]}`

func TestBloodHoundCrossCollectionDirectedPath(t *testing.T) {
	for _, test := range []struct {
		name, start, end string
		steps            int
	}{
		{"membership then ACL", "S-1-5-21-1", "S-1-5-21-4", 2},
		{"reverse direction", "S-1-5-21-4", "S-1-5-21-1", 0},
		{"same display name", "S-1-5-21-2", "S-1-5-21-4", 0},
		{"zero hop", "S-1-5-21-1", "S-1-5-21-1", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, err := auditBloodHound(context.Background(), bloodHoundRequest(t, test.start, test.end, bloodHoundUsers, bloodHoundGroup, bloodHoundTarget))
			if err != nil {
				t.Fatal(err)
			}
			steps := 0
			for _, observation := range r.Observations {
				if observation.Kind == "candidate path step" {
					steps++
				}
			}
			if steps != test.steps {
				t.Fatalf("got %d steps, want %d: %+v", steps, test.steps, r)
			}
			if len(r.Nodes) != 4 || len(r.Edges) != 2 {
				t.Fatalf("unexpected graph: %+v", r)
			}
			encoded, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "PRIVATE_SECRET") || strings.Contains(string(encoded), "same-name") {
				t.Fatal("unneeded object properties leaked")
			}
		})
	}
}

func TestBloodHoundUnknownRightsDuplicatesCyclesAndFlags(t *testing.T) {
	collection := `{"meta":{"type":"users","version":6},"data":[
	{"ObjectIdentifier":"A","Properties":{"enabled":true},"Aces":[{"PrincipalSID":"B","RightName":"GenericAll"}]},
	{"ObjectIdentifier":"B","Properties":{"enabled":true},"Aces":[{"PrincipalSID":"A","RightName":"UnrecognizedRight"}]},
	{"ObjectIdentifier":"C","Properties":{"enabled":true},"Aces":[{"PrincipalSID":"B","RightName":"WriteDacl"}]},
	{"ObjectIdentifier":"D","Aces":[{"PrincipalSID":"MISSING","RightName":"GenericAll"}]}
	]}`
	r, err := auditBloodHound(context.Background(), bloodHoundRequest(t, "A", "C", collection, collection))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 || len(r.Nodes) != 4 || len(r.Edges) != 3 {
		t.Fatalf("unknown rights traversed or graph not deduplicated: %+v", r)
	}
	if !r.Limited || !strings.Contains(strings.Join(r.Gaps, " "), "enabled flags are missing") {
		t.Fatal("missing incomplete identity or state gaps")
	}
	fakeMembership := strings.ReplaceAll(collection, "UnrecognizedRight", "MemberOf")
	r, err = auditBloodHound(context.Background(), bloodHoundRequest(t, "A", "C", fakeMembership))
	if err != nil || len(r.Findings) != 0 {
		t.Fatalf("ACE right masquerading as membership traversed: %v %+v", err, r)
	}
	known := strings.ReplaceAll(collection, "UnrecognizedRight", "GenericWrite")
	r, err = auditBloodHound(context.Background(), bloodHoundRequest(t, "A", "C", known))
	if err != nil || len(r.Findings) != 1 {
		t.Fatalf("expected path through cycle: %v %+v", err, r)
	}
	disabled := strings.Replace(known, `"ObjectIdentifier":"B","Properties":{"enabled":true}`, `"ObjectIdentifier":"B","Properties":{"enabled":false}`, 1)
	r, err = auditBloodHound(context.Background(), bloodHoundRequest(t, "A", "C", known, disabled))
	if err != nil || len(r.Findings) != 0 {
		t.Fatalf("disabled duplicate object traversed: %v %+v", err, r)
	}
}

func TestBloodHoundInputValidation(t *testing.T) {
	valid := bloodHoundRequest(t, "S-1-5-21-1", "S-1-5-21-4", bloodHoundUsers, bloodHoundGroup, bloodHoundTarget)
	for name, req := range map[string]ToolRequest{
		"engine":               {Input: valid.Input, RunEngine: true},
		"live target":          {Input: valid.Input, Target: "example.test"},
		"invalid JSON":         {Input: `{"collections":[PRIVATE_SECRET`},
		"unknown field":        {Input: strings.TrimSuffix(valid.Input, "}") + `,"PRIVATE_SECRET":true}`},
		"trailing JSON":        {Input: valid.Input + ` {}`},
		"uncollected endpoint": bloodHoundRequest(t, "MISSING", "S-1-5-21-4", bloodHoundUsers, bloodHoundTarget),
		"display name":         bloodHoundRequest(t, "same-name", "S-1-5-21-4", bloodHoundUsers, bloodHoundTarget),
		"bad version":          bloodHoundRequest(t, "S-1-5-21-1", "S-1-5-21-1", strings.Replace(bloodHoundUsers, `"version":6`, `"version":7`, 1)),
		"empty collections":    {Input: `{"collections":[],"start":"A","end":"B"}`},
		"malformed member":     bloodHoundRequest(t, "S-1-5-21-1", "S-1-5-21-1", bloodHoundUsers, strings.Replace(bloodHoundGroup, `"ObjectIdentifier":"S-1-5-21-1"`, `"ObjectIdentifier":""`, 1)),
		"ID normalization":     bloodHoundRequest(t, "A?token=PRIVATE_SECRET", "B", bloodHoundUsers),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := auditBloodHound(context.Background(), req)
			if err == nil {
				t.Fatal("expected rejection")
			}
			if strings.Contains(err.Error(), "PRIVATE_SECRET") {
				t.Fatal("error echoed private input")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditBloodHound(ctx, valid); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation: %v", err)
	}
}

func TestBloodHoundCollectionAndRecordLimits(t *testing.T) {
	collections := make([]string, 21)
	for index := range collections {
		collections[index] = bloodHoundUsers
	}
	if _, err := auditBloodHound(context.Background(), bloodHoundRequest(t, "S-1-5-21-1", "S-1-5-21-2", collections...)); err == nil {
		t.Fatal("accepted 21 collections")
	}
	objects := strings.TrimSuffix(strings.Repeat(`{"ObjectIdentifier":"A"},`, 1001), ",")
	large := `{"meta":{"type":"users","version":6},"data":[` + objects + `]}`
	if _, err := auditBloodHound(context.Background(), bloodHoundRequest(t, "A", "A", large)); err == nil {
		t.Fatal("accepted record budget overflow through duplicates")
	}
	if _, err := auditBloodHound(context.Background(), ToolRequest{Input: strings.Repeat("x", MaxInput+1)}); err == nil {
		t.Fatal("accepted oversized input")
	}
}
