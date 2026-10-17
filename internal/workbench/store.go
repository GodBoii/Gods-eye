// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
)

type Summary struct {
	ID               string `json:"id"`
	Tool             string `json:"tool"`
	Summary          string `json:"summary"`
	CreatedAt        string `json:"createdAt"`
	FindingCount     int    `json:"findingCount"`
	ObservationCount int    `json:"observationCount"`
	Limited          bool   `json:"limited"`
}

// Store owns immutable reports. Only normalized evidence is written to disk.
type Store struct {
	mu        sync.Mutex
	directory string
	reports   []*Report
}

func OpenStore(directory string) (*Store, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("create evidence directory: %w", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	s := &Store{directory: directory, reports: []*Report{}}
	validName := regexp.MustCompile(`^[A-Za-z0-9]{26}\.json$`)
	for _, entry := range entries {
		if !validName.MatchString(entry.Name()) {
			continue
		}
		if len(s.reports) >= 100 {
			return nil, fmt.Errorf("evidence storage has more than 100 reports; archive excess reports before restarting")
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return nil, fmt.Errorf("evidence files must be regular JSON files")
		}
		input, err := os.Open(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(input, MaxInput+1))
		closeErr := input.Close()
		if readErr != nil || closeErr != nil {
			return nil, fmt.Errorf("read saved evidence failed")
		}
		if len(data) > MaxInput {
			return nil, fmt.Errorf("saved evidence exceeds limit")
		}
		var report Report
		if err := decodeJSON(data, &report); err != nil || report.ID+".json" != entry.Name() || report.Tool == "" || report.CreatedAt.IsZero() || len(report.Nodes) > maxRecords || len(report.Edges) > maxRecords || len(report.Findings) > maxRecords || len(report.Observations) > maxRecords || len(report.Artifacts) > 32 {
			return nil, fmt.Errorf("invalid saved evidence: %s", entry.Name())
		}
		// Preserve array-shaped API fields when reading a manually edited file.
		if report.Findings == nil {
			report.Findings = []Finding{}
		}
		if report.Observations == nil {
			report.Observations = []Observation{}
		}
		if report.Nodes == nil {
			report.Nodes = []Node{}
		}
		if report.Edges == nil {
			report.Edges = []Edge{}
		}
		if report.Artifacts == nil {
			report.Artifacts = []Artifact{}
		}
		if report.Gaps == nil {
			report.Gaps = []string{}
		}
		s.reports = append(s.reports, &report)
	}
	sort.Slice(s.reports, func(i, j int) bool { return s.reports[i].CreatedAt.After(s.reports[j].CreatedAt) })
	if err := s.trim(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) trim() error {
	for len(s.reports) > 20 {
		last := s.reports[len(s.reports)-1]
		if err := os.Remove(filepath.Join(s.directory, last.ID+".json")); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("prune old evidence: %w", err)
		}
		s.reports = s.reports[:len(s.reports)-1]
	}
	return nil
}

func (s *Store) Save(r *Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.ID = rand.Text()
	data, err := json.Marshal(r)
	if err != nil || len(data) > MaxInput {
		return fmt.Errorf("evidence exceeds storage limit")
	}
	// Write a temporary file, sync, then rename so a restart never reads a
	// half-written report. The random ID names only files owned by this store.
	temp, err := os.CreateTemp(s.directory, "evidence-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	_, writeErr := temp.Write(data)
	syncErr := temp.Sync()
	closeErr := temp.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return fmt.Errorf("could not write evidence")
	}
	if err := os.Rename(temp.Name(), filepath.Join(s.directory, r.ID+".json")); err != nil {
		return err
	}
	s.reports = append([]*Report{r}, s.reports...)
	return s.trim()
}

func (s *Store) List() []Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]Summary, 0, len(s.reports))
	for _, r := range s.reports {
		items = append(items, Summary{r.ID, r.Tool, r.Summary, r.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), len(r.Findings), len(r.Observations), r.Limited})
	}
	return items
}

func (s *Store) Get(id string) *Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.reports {
		if r.ID == id {
			return r
		}
	}
	return nil
}
