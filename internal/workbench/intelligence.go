// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const intelligenceLimit = 5000

type EvidenceReference struct {
	ReportID    string    `json:"reportId"`
	FindingID   string    `json:"findingId"`
	Tool        string    `json:"tool"`
	Severity    string    `json:"severity"`
	RecordedAt  time.Time `json:"recordedAt"`
	InputSHA256 string    `json:"inputSha256"`
}

type IntelligenceFinding struct {
	ID         string              `json:"id"`
	EntityID   string              `json:"entityId"`
	Title      string              `json:"title"`
	Target     string              `json:"target"`
	Detail     string              `json:"detail"`
	Severity   string              `json:"severity"`
	FirstSeen  time.Time           `json:"firstSeen"`
	LastSeen   time.Time           `json:"lastSeen"`
	References []EvidenceReference `json:"references"`
}

type IntelligenceEntity struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Label        string   `json:"label"`
	ReportIDs    []string `json:"reportIds"`
	FindingCount int      `json:"findingCount"`
}

type IntelligenceRelation struct {
	Source    string   `json:"source"`
	Target    string   `json:"target"`
	Relation  string   `json:"relation"`
	ReportIDs []string `json:"reportIds"`
}

type Intelligence struct {
	GeneratedAt time.Time              `json:"generatedAt"`
	ReportCount int                    `json:"reportCount"`
	Entities    []IntelligenceEntity   `json:"entities"`
	Findings    []IntelligenceFinding  `json:"findings"`
	Relations   []IntelligenceRelation `json:"relations"`
	Reports     []Summary              `json:"reports"`
	Limited     bool                   `json:"limited"`
	Gaps        []string               `json:"gaps"`
}

// Intelligence takes one consistent snapshot of the retained immutable reports.
func (s *Store) Intelligence(now time.Time) Intelligence {
	s.mu.Lock()
	reports := append([]*Report{}, s.reports...)
	s.mu.Unlock()
	return buildIntelligence(reports, now)
}

func buildIntelligence(reports []*Report, now time.Time) Intelligence {
	result := Intelligence{GeneratedAt: now.UTC(), ReportCount: len(reports), Entities: []IntelligenceEntity{}, Findings: []IntelligenceFinding{}, Relations: []IntelligenceRelation{}, Reports: []Summary{}, Gaps: []string{
		"Only the newest 20 retained normalized reports are connected. First/last seen are report recording times, not proof of when a vulnerability existed or was fixed.",
		"Exact host matching connects URLs, DNS names and IP literals. Shared infrastructure and imported relationships do not establish common ownership, identity or an attack path.",
		"Severity is reported by the source. Repeated reports and multiple tool names are not independent verification. Findings remain candidates until reviewed; no exploitability or remediation status is inferred.",
	}}
	entities := map[string]int{}
	findings := map[string]int{}
	relations := map[string]int{}
	entity := func(target, reportID string) string {
		kind, label := intelligenceIdentity(target)
		if label == "" {
			return ""
		}
		id := digest([]byte(kind + "\x00" + label))[:24]
		if index, ok := entities[id]; ok {
			result.Entities[index].ReportIDs = uniqueAppend(result.Entities[index].ReportIDs, reportID)
			return id
		}
		if len(result.Entities) >= intelligenceLimit {
			result.Limited = true
			return ""
		}
		entities[id] = len(result.Entities)
		result.Entities = append(result.Entities, IntelligenceEntity{ID: id, Kind: kind, Label: label, ReportIDs: []string{reportID}})
		return id
	}
	for _, r := range reports {
		result.Reports = append(result.Reports, Summary{r.ID, r.Tool, r.Summary, r.CreatedAt.Format(time.RFC3339), len(r.Findings), len(r.Observations), r.Limited})
		result.Limited = result.Limited || r.Limited
		for _, f := range r.Findings {
			target := intelligenceTarget(f.Target)
			// Preserve distinct details/advisories on the same endpoint. Case in
			// paths and opaque identifiers is significant.
			id := digest([]byte(strings.Join([]string{f.Title, target, f.Detail}, "\x00")))[:24]
			ref := EvidenceReference{r.ID, f.ID, r.Tool, intelligenceSeverity(f.Severity), r.CreatedAt, r.InputSHA256}
			if index, ok := findings[id]; ok {
				item := &result.Findings[index]
				item.References = append(item.References, ref)
				if severityRank(ref.Severity) < severityRank(item.Severity) {
					item.Severity = ref.Severity
				}
				if r.CreatedAt.Before(item.FirstSeen) {
					item.FirstSeen = r.CreatedAt
				}
				if r.CreatedAt.After(item.LastSeen) {
					item.LastSeen = r.CreatedAt
				}
				continue
			}
			if len(result.Findings) >= intelligenceLimit {
				result.Limited = true
				continue
			}
			entityID := entity(target, r.ID)
			if entityID != "" {
				result.Entities[entities[entityID]].FindingCount++
			}
			findings[id] = len(result.Findings)
			result.Findings = append(result.Findings, IntelligenceFinding{id, entityID, text(f.Title), target, text(f.Detail), ref.Severity, r.CreatedAt, r.CreatedAt, []EvidenceReference{ref}})
		}
		nodes := map[string]string{}
		for _, n := range r.Nodes {
			// Only explicit infrastructure node kinds can merge into hosts.
			switch strings.ToLower(n.Kind) {
			case "domain", "ip", "host", "url", "asset", "service":
				nodes[n.ID] = entity(n.Label, r.ID)
			}
		}
		for _, o := range r.Observations {
			entity(o.Target, r.ID)
		}
		for _, e := range r.Edges {
			source, target := nodes[e.Source], nodes[e.Target]
			if source == "" || target == "" || source == target {
				continue
			}
			id := source + "\x00" + target + "\x00" + text(e.Relation)
			if index, ok := relations[id]; ok {
				result.Relations[index].ReportIDs = uniqueAppend(result.Relations[index].ReportIDs, r.ID)
				continue
			}
			if len(result.Relations) >= intelligenceLimit {
				result.Limited = true
				continue
			}
			relations[id] = len(result.Relations)
			result.Relations = append(result.Relations, IntelligenceRelation{source, target, text(e.Relation), []string{r.ID}})
		}
	}
	// A duplicate finding still associates every source report with its entity.
	for _, f := range result.Findings {
		if index, ok := entities[f.EntityID]; ok {
			for _, ref := range f.References {
				result.Entities[index].ReportIDs = uniqueAppend(result.Entities[index].ReportIDs, ref.ReportID)
			}
		}
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) < severityRank(b.Severity)
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.ID < b.ID
	})
	sort.Slice(result.Entities, func(i, j int) bool {
		a, b := result.Entities[i], result.Entities[j]
		if a.FindingCount != b.FindingCount {
			return a.FindingCount > b.FindingCount
		}
		return a.Label < b.Label
	})
	if result.Limited {
		result.Gaps = append(result.Gaps, "One or more source reports are limited, or the 5,000 findings/entities/relations limit was reached. Inspect each source report's coverage notes.")
	}
	return result
}

func uniqueAppend(items []string, item string) []string {
	for _, old := range items {
		if old == item {
			return items
		}
	}
	return append(items, item)
}

func intelligenceSeverity(value string) string {
	switch value {
	case "critical", "high", "medium", "low", "info":
		return value
	}
	return "info"
}

func severityRank(value string) int {
	switch value {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func intelligenceTarget(value string) string {
	value = Target(value)
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return value
	}
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
		if strings.Contains(u.Host, ":") {
			u.Host = "[" + u.Host + "]"
		}
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

func intelligenceIdentity(value string) (string, string) {
	value = intelligenceTarget(value)
	if value == "" {
		return "", ""
	}
	if strings.HasPrefix(value, "source:") {
		return "target", value
	}
	original := value
	explicitHost := false
	u, err := url.Parse(value)
	if err == nil && u.Hostname() != "" && (u.Scheme == "http" || u.Scheme == "https") {
		value = u.Hostname()
		explicitHost = true
	} else if host, portText, err := net.SplitHostPort(value); err == nil {
		port, err := strconv.Atoi(portText)
		if err == nil && port >= 1 && port <= 65535 && validHost(host) {
			value, explicitHost = host, true
		}
	}
	if ip := net.ParseIP(value); ip != nil {
		return "host", ip.String()
	}
	if validHost(value) && (explicitHost || strings.Contains(value, ".")) && !strings.ContainsAny(value, "/\\@:") {
		return "host", strings.TrimSuffix(strings.ToLower(value), ".")
	}
	return "target", original
}
