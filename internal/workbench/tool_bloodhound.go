// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

type bloodHoundCollection struct {
	Meta struct {
		Type    string `json:"type"`
		Version int    `json:"version"`
	} `json:"meta"`
	Data []bloodHoundObject `json:"data"`
}

type bloodHoundObject struct {
	ID         string `json:"ObjectIdentifier"`
	Properties struct {
		Enabled *bool `json:"enabled"`
	} `json:"Properties"`
	Aces []struct {
		SID   string `json:"PrincipalSID"`
		Right string `json:"RightName"`
	} `json:"Aces"`
	Members []struct {
		ID string `json:"ObjectIdentifier"`
	} `json:"Members"`
}

type bloodHoundRelationship struct {
	source, target, relation string
	permitted                bool
}

// auditBloodHound searches supplied directory evidence, without collecting data
// or asserting that a reported permission is effective in a live directory.
func auditBloodHound(ctx context.Context, req ToolRequest) (*Report, error) {
	if req.RunEngine || req.Target != "" {
		return nil, fmt.Errorf("BloodHound path analysis accepts offline collection JSON only")
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
		Collections []json.RawMessage `json:"collections"`
		Start       string            `json:"start"`
		End         string            `json:"end"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("expected collections, start and end JSON fields")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("provide exactly one JSON object")
	}
	if len(input.Collections) < 1 || len(input.Collections) > 20 {
		return nil, fmt.Errorf("provide 1 to 20 BloodHound collections")
	}
	if !bloodHoundID(input.Start) || !bloodHoundID(input.End) {
		return nil, fmt.Errorf("start and end must be exact ObjectIdentifier values of 1 to 512 bytes")
	}
	r := newReport("bloodhound", "Offline BloodHound reported-control path analysis completed.", data)
	r.gap("Paths are candidate reported-control chains requiring effective-access verification; no collection, exploitation or live directory access was performed.")
	r.gap("Only MemberOf, GenericAll, GenericWrite, WriteDacl, WriteOwner, AddMember, ForceChangePassword and AddKeyCredentialLink relationships are traversed. Conditional permissions, deny ACEs, inheritance and actual credential availability require separate verification.")
	objects := make(map[string]bool)
	disabled := make(map[string]bool)
	nodes := make(map[string]string)
	var edges []bloodHoundRelationship
	// Count raw records and relationships as well as unique graph elements so
	// duplicate evidence cannot bypass the work budget.
	budget := 0
	for _, raw := range input.Collections {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var collection bloodHoundCollection
		if err := decodeJSON(raw, &collection); err != nil {
			return nil, fmt.Errorf("invalid BloodHound collection JSON")
		}
		if collection.Data == nil || collection.Meta.Type == "" || collection.Meta.Version < 5 || collection.Meta.Version > 6 {
			return nil, fmt.Errorf("expected BloodHound v5/v6 collections with data and meta")
		}
		for _, obj := range collection.Data {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			budget += 1 + len(obj.Aces) + len(obj.Members)
			if budget > 1000 {
				return nil, fmt.Errorf("collections exceed the combined 1,000 object/relationship limit")
			}
			if !bloodHoundID(obj.ID) {
				return nil, fmt.Errorf("collection has an invalid ObjectIdentifier")
			}
			objects[obj.ID] = true
			if obj.Properties.Enabled != nil && !*obj.Properties.Enabled {
				disabled[obj.ID] = true
				r.gap("Disabled directory objects were reported; paths through them are excluded. Conflicting enabled flags are treated as disabled.")
			}
			if obj.Properties.Enabled == nil && (collection.Meta.Type == "users" || collection.Meta.Type == "computers") {
				r.gap("Some user or computer enabled flags are missing; account usability is unverified.")
			}
			for _, ace := range obj.Aces {
				if !bloodHoundID(ace.SID) || ace.Right == "" || len(ace.Right) > 128 || text(ace.Right) != ace.Right {
					return nil, fmt.Errorf("collection has an invalid permission endpoint or right")
				}
				edges = append(edges, bloodHoundRelationship{ace.SID, obj.ID, ace.Right, ace.Right != "MemberOf" && bloodHoundRight(ace.Right)})
			}
			for _, member := range obj.Members {
				if !bloodHoundID(member.ID) {
					return nil, fmt.Errorf("collection has an invalid member endpoint")
				}
				edges = append(edges, bloodHoundRelationship{member.ID, obj.ID, "MemberOf", true})
			}
		}
	}
	if !objects[input.Start] || !objects[input.End] {
		return nil, fmt.Errorf("start and end must exist as collected objects; names and reference-only identities are not accepted")
	}
	identifiers := make([]string, 0, len(objects))
	for sid := range objects {
		identifiers = append(identifiers, sid)
	}
	sort.Strings(identifiers)
	for _, sid := range identifiers {
		nodes[sid] = r.node("directory object", sid)
	}
	// BFS behavior follows supplied edge order. Only fully
	// collected identities participate, preventing reference-only shortcuts.
	adjacency := make(map[string][]Edge)
	for _, edge := range edges {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !objects[edge.source] || !objects[edge.target] {
			r.Limited = true
			r.gap("Some relationship endpoints have no collected object; those relationships are excluded from path search.")
			continue
		}
		r.edge(nodes[edge.source], nodes[edge.target], edge.relation)
		if !edge.permitted {
			r.gap("Unknown or unsupported permission relationships are retained as evidence but excluded from path search.")
			continue
		}
		if disabled[edge.source] || disabled[edge.target] {
			continue
		}
		adjacency[edge.source] = append(adjacency[edge.source], Edge{edge.source, edge.target, edge.relation})
	}
	if disabled[input.Start] || disabled[input.End] {
		r.observe("path search", input.End, "No candidate path searched because an endpoint is reported disabled.")
		return r, nil
	}
	queue := []string{input.Start}
	seen := map[string]bool{input.Start: true}
	previous := make(map[string]Edge)
	for index := 0; index < len(queue) && !seen[input.End]; index++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, edge := range adjacency[queue[index]] {
			if seen[edge.Target] {
				continue
			}
			seen[edge.Target] = true
			previous[edge.Target] = edge
			queue = append(queue, edge.Target)
		}
	}
	if !seen[input.End] {
		r.observe("path search", input.End, "No candidate path in supplied permitted relationships. This does not establish absence of directory attack paths.")
		return r, nil
	}
	if input.Start == input.End {
		r.observe("path search", input.Start, "Start equals end; zero-hop identity match is not a reported-control chain.")
		return r, nil
	}
	var path []Edge
	for current := input.End; current != input.Start; {
		edge := previous[current]
		path = append(path, edge)
		current = edge.Source
	}
	for index := len(path) - 1; index >= 0; index-- {
		edge := path[index]
		r.observe("candidate path step", edge.Source, edge.Relation+" -> "+edge.Target)
	}
	r.finding("info", "Candidate reported-control chain", input.End, fmt.Sprintf("A %d-hop directed chain connects the supplied identities. Verify effective access, account state and each relationship before treating this as an attack path.", len(path)))
	return r, nil
}

func bloodHoundID(value string) bool {
	return value != "" && len(value) <= 512 && text(value) == value && Target(value) == value && !strings.ContainsAny(value, " /\\:@")
}

func bloodHoundRight(value string) bool {
	switch value {
	case "MemberOf", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "AddMember", "ForceChangePassword", "AddKeyCredentialLink":
		return true
	default:
		return false
	}
}
