// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// auditMaltego correlates supplied evidence only. It never runs transforms or
// infers that two differently labelled entities represent the same person.
func auditMaltego(ctx context.Context, req ToolRequest) (*Report, error) {
	if req.RunEngine || req.Target != "" {
		return nil, fmt.Errorf("relationship analysis accepts offline report JSON only")
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
	var input struct {
		Reports []Report `json:"reports"`
		From    string   `json:"from"`
		To      string   `json:"to"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("invalid normalized report collection: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("provide exactly one JSON collection")
	}
	if len(input.Reports) == 0 || len(input.Reports) > 20 {
		return nil, fmt.Errorf("provide 1 to 20 reports")
	}
	if (input.From == "") != (input.To == "") {
		return nil, fmt.Errorf("provide both from and to labels")
	}
	if len(input.From) > 512 || len(input.To) > 512 {
		return nil, fmt.Errorf("path labels exceed 512 bytes")
	}
	r := newReport("maltego", "Offline relationship correlation completed.", data)
	r.gap("Entities merge only when kind and sanitized label match exactly; case, aliases and different entity kinds are not inferred to be equivalent. URL credentials, queries and fragments are removed.")
	r.gap("Only supplied directed relationships are searched; a path is evidence connectivity, not proof of identity, exploitability or causation. No network transforms or personal-data enrichment.")
	// A single combined collection budget also bounds provenance observations.
	total := 0
	nodeSources := map[string][]int{}
	edgeSources := map[Edge][]int{}
	for reportIndex, source := range input.Reports {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		total += len(source.Nodes) + len(source.Edges)
		if total > 1000 {
			return nil, fmt.Errorf("reports exceed the combined 1,000 node/edge input limit")
		}
		if source.Limited {
			r.Limited = true
			r.gap("At least one source report contains incomplete evidence.")
		}
		ids := map[string]string{}
		for _, n := range source.Nodes {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !maltegoID(n.ID) || ids[n.ID] != "" || !maltegoField(n.Kind, 64) || !maltegoField(n.Label, 512) || Target(n.Label) == "" {
				return nil, fmt.Errorf("report %d has an invalid or duplicate node", reportIndex+1)
			}
			id := r.node(n.Kind, n.Label)
			ids[n.ID] = id
			nodeSources[id] = maltegoProvenance(nodeSources[id], reportIndex+1)
		}
		for _, e := range source.Edges {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !maltegoID(e.Source) || !maltegoID(e.Target) || ids[e.Source] == "" || ids[e.Target] == "" || !maltegoField(e.Relation, 64) {
				return nil, fmt.Errorf("report %d has an invalid or dangling edge", reportIndex+1)
			}
			merged := Edge{ids[e.Source], ids[e.Target], e.Relation}
			r.edge(merged.Source, merged.Target, merged.Relation)
			edgeSources[merged] = maltegoProvenance(edgeSources[merged], reportIndex+1)
		}
	}
	// Preserve provenance without copying findings, request bodies or source metadata.
	for _, n := range r.Nodes {
		payload, err := json.Marshal(struct {
			Node    string `json:"node"`
			Reports []int  `json:"reports"`
		}{n.ID, nodeSources[n.ID]})
		if err != nil {
			return nil, err
		}
		r.observe("entity provenance", n.Label, string(payload))
	}
	for _, e := range r.Edges {
		payload, err := json.Marshal(struct {
			Edge    Edge  `json:"edge"`
			Reports []int `json:"reports"`
		}{e, edgeSources[e]})
		if err != nil {
			return nil, err
		}
		r.observe("relationship provenance", "", string(payload))
	}
	if input.From != "" {
		if err := maltegoPath(ctx, r, Target(input.From), Target(input.To)); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.Summary = fmt.Sprintf("Correlated %d reports into %d entities and %d directed relationships.", len(input.Reports), len(r.Nodes), len(r.Edges))
	return r, nil
}

func maltegoID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.:", c)) {
			return false
		}
	}
	return true
}

func maltegoField(s string, max int) bool { return s != "" && len(s) <= max && text(s) == s }

func maltegoProvenance(existing []int, index int) []int {
	if len(existing) == 0 || existing[len(existing)-1] != index {
		return append(existing, index)
	}
	return existing
}

func maltegoPath(ctx context.Context, r *Report, from, to string) error {
	resolve := func(label string) (string, error) {
		id := ""
		for _, n := range r.Nodes {
			if n.Label == label {
				if id != "" {
					return "", fmt.Errorf("path label is ambiguous across entity kinds")
				}
				id = n.ID
			}
		}
		if id == "" {
			return "", fmt.Errorf("path label does not exist in supplied reports")
		}
		return id, nil
	}
	start, err := resolve(from)
	if err != nil {
		return err
	}
	end, err := resolve(to)
	if err != nil {
		return err
	}
	adj := map[string][]Edge{}
	for _, e := range r.Edges {
		adj[e.Source] = append(adj[e.Source], e)
	}
	queue := []string{start}
	seen := map[string]bool{start: true}
	parents := map[string]Edge{}
	for i := 0; i < len(queue) && !seen[end]; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, e := range adj[queue[i]] {
			if !seen[e.Target] {
				seen[e.Target] = true
				parents[e.Target] = e
				queue = append(queue, e.Target)
			}
		}
	}
	if !seen[end] {
		r.observe("relationship path", from, "No directed path to the selected destination exists in the supplied evidence.")
		return nil
	}
	path := []Edge{}
	for id := end; id != start; {
		e := parents[id]
		path = append(path, e)
		id = e.Source
	}
	if len(path) > 32 {
		r.Limited = true
		r.gap("The shortest directed path exceeds the 32-hop output limit; path detail was omitted.")
		return nil
	}
	// Reserve path observations without losing provenance at the collection bound.
	if len(r.Observations)+len(path)+1 > maxRecords {
		r.Limited = true
		r.gap("Path output omitted to preserve complete relationship provenance within the observation limit.")
		return nil
	}
	r.observe("relationship path", from, fmt.Sprintf("Shortest directed path to selected destination: %d hops.", len(path)))
	for i := len(path) - 1; i >= 0; i-- {
		payload, err := json.Marshal(struct {
			Step int  `json:"step"`
			Edge Edge `json:"edge"`
		}{len(path) - i, path[i]})
		if err != nil {
			return err
		}
		r.observe("relationship path hop", "", string(payload))
	}
	return nil
}
