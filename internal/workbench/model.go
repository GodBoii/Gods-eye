// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const MaxInput = 8 << 20
const maxRecords = 1000

type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Target   string `json:"target"`
	Detail   string `json:"detail"`
}

type Observation struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Value  string `json:"value"`
}

type Node struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

type Edge struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Relation string `json:"relation"`
}

// Artifact describes a byte range in the original file, never an executed file.
type Artifact struct {
	Name   string `json:"name"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
}

type Report struct {
	ID           string        `json:"id"`
	Tool         string        `json:"tool"`
	Summary      string        `json:"summary"`
	CreatedAt    time.Time     `json:"createdAt"`
	InputSHA256  string        `json:"inputSha256"`
	Findings     []Finding     `json:"findings"`
	Observations []Observation `json:"observations"`
	Nodes        []Node        `json:"nodes"`
	Edges        []Edge        `json:"edges"`
	Artifacts    []Artifact    `json:"artifacts"`
	Gaps         []string      `json:"gaps"`
	Limited      bool          `json:"limited"`
}

func newReport(tool, summary string, data []byte) *Report {
	r := &Report{Tool: tool, Summary: summary, CreatedAt: time.Now().UTC(), Findings: []Finding{}, Observations: []Observation{}, Nodes: []Node{}, Edges: []Edge{}, Artifacts: []Artifact{}, Gaps: []string{}}
	if data != nil {
		r.InputSHA256 = digest(data)
	}
	return r
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func text(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	runes := []rune(strings.TrimSpace(value))
	if len(runes) > 512 {
		runes = runes[:512]
	}
	return string(runes)
}

// Only URL origin and path are retained. Query strings often carry credentials.
func Target(value string) string {
	value = text(value)
	parsed, err := url.Parse(value)
	if err == nil && parsed.Host != "" {
		parsed.RawQuery, parsed.Fragment, parsed.RawFragment, parsed.User = "", "", "", nil
		return text(parsed.String())
	}
	if i := strings.IndexAny(value, "?#"); i >= 0 {
		value = value[:i]
	}
	return value
}

func (r *Report) gap(value string) {
	value = text(value)
	for _, item := range r.Gaps {
		if item == value {
			return
		}
	}
	if len(r.Gaps) < 30 {
		r.Gaps = append(r.Gaps, value)
	}
}

func (r *Report) limit() {
	r.Limited = true
	r.gap("The 1,000-record collection limit was reached; review the original input for omitted evidence.")
}

func (r *Report) observe(kind, target, value string) {
	if len(r.Observations) >= maxRecords {
		r.limit()
		return
	}
	r.Observations = append(r.Observations, Observation{text(kind), Target(target), text(value)})
}

func (r *Report) finding(severity, title, target, detail string) {
	f := Finding{Title: text(title), Severity: strings.ToLower(severity), Target: Target(target), Detail: text(detail)}
	switch f.Severity {
	case "critical", "high", "medium", "low", "info":
	default:
		f.Severity = "info"
	}
	f.ID = digest([]byte(strings.Join([]string{r.Tool, f.Title, f.Target, f.Detail}, "\x00")))[:24]
	for _, existing := range r.Findings {
		if existing.ID == f.ID {
			return
		}
	}
	if len(r.Findings) >= maxRecords {
		r.limit()
		return
	}
	r.Findings = append(r.Findings, f)
}

func (r *Report) node(kind, label string) string {
	label, kind = Target(label), text(kind)
	id := digest([]byte(kind + "\x00" + label))[:24]
	for _, n := range r.Nodes {
		if n.ID == id {
			return id
		}
	}
	if len(r.Nodes) >= maxRecords {
		r.limit()
		return ""
	}
	r.Nodes = append(r.Nodes, Node{id, kind, label})
	return id
}

func (r *Report) edge(source, target, relation string) {
	if source == "" || target == "" {
		return
	}
	e := Edge{source, target, text(relation)}
	for _, old := range r.Edges {
		if old == e {
			return
		}
	}
	if len(r.Edges) >= maxRecords {
		r.limit()
		return
	}
	r.Edges = append(r.Edges, e)
}

func checkInput(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("the input is empty")
	}
	if len(data) > MaxInput {
		return fmt.Errorf("input exceeds the 8 MiB limit")
	}
	return nil
}
