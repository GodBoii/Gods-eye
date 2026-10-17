// SPDX-License-Identifier: Apache-2.0
package dashboard

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"godseye/internal/report"
	"godseye/internal/secrets"
	"godseye/internal/webcheck"
	"godseye/internal/world"
)

type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        uint32 `json:"line"`
	Description string `json:"description"`
}
type Run struct {
	ID           string           `json:"id"`
	Target       string           `json:"target"`
	Kind         string           `json:"kind"`
	Status       string           `json:"status"`
	StartedAt    time.Time        `json:"startedAt"`
	FinishedAt   *time.Time       `json:"finishedAt"`
	Files        int              `json:"files"`
	FindingCount int              `json:"findingCount"`
	Findings     []Finding        `json:"findings"`
	Checks       []webcheck.Check `json:"checks"`
	Gaps         []string         `json:"gaps"`
	Error        string           `json:"error"`
	jsonReport   []byte
	sarifReport  []byte
	cancel       context.CancelFunc
}
type Server struct {
	mu      sync.Mutex
	root    string
	file    string
	assets  []Asset
	runs    []*Run
	context context.Context
	world   *world.Service
}

func New(ctx context.Context, root, stateDir string) (*Server, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("workspace must be a directory")
	}
	file := filepath.Join(stateDir, "assets.json")
	assets, err := loadAssets(file)
	if err != nil {
		return nil, err
	}
	return &Server{root: absolute, file: file, assets: assets, runs: []*Run{}, context: ctx, world: world.New(filepath.Join(stateDir, "world-cache"))}, nil
}

func (s *Server) Handler(host, dist string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", s.state)
	mux.HandleFunc("GET /api/world/{layer}", func(w http.ResponseWriter, r *http.Request) {
		snapshot, ok := s.world.Snapshot(r.Context(), r.PathValue("layer"))
		if !ok {
			fail(w, 404, "Unknown public data layer")
			return
		}
		send(w, 200, snapshot)
	})
	mux.HandleFunc("POST /api/assets", s.addAsset)
	mux.HandleFunc("DELETE /api/assets/{id}", s.removeAsset)
	mux.HandleFunc("POST /api/runs", s.startRun)
	mux.HandleFunc("GET /api/runs/{id}", s.runDetail)
	mux.HandleFunc("POST /api/runs/{id}/cancel", s.cancelRun)
	mux.HandleFunc("GET /api/runs/{id}/report", s.download)
	mux.Handle("/", http.FileServer(http.Dir(dist)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host {
			http.Error(w, "Host not allowed", 403)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+host {
			http.Error(w, "Origin not allowed", 403)
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "Cross-site request denied", 403)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Header.Get("X-GodsEye-Request") != "1" {
			http.Error(w, "Missing request header", 403)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		mux.ServeHTTP(w, r)
	})
}

func send(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, message string) {
	send(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		fail(w, 400, "Invalid JSON request")
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		fail(w, 400, "Expected one JSON object")
		return false
	}
	return true
}
func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	runs := make([]Run, 0, len(s.runs))
	for _, run := range s.runs {
		summary := *run
		summary.Findings = []Finding{}
		summary.Checks = []webcheck.Check{}
		runs = append(runs, summary)
	}
	assets := append([]Asset{}, s.assets...)
	s.mu.Unlock()
	send(w, 200, map[string]any{"workspace": s.root, "assets": assets, "runs": runs})
}

func (s *Server) runDetail(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	for _, run := range s.runs {
		if run.ID == r.PathValue("id") {
			snapshot := *run
			s.mu.Unlock()
			send(w, 200, snapshot)
			return
		}
	}
	s.mu.Unlock()
	fail(w, 404, "Check not found")
}
func (s *Server) addAsset(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		Target string `json:"target"`
		Owner  string `json:"owner"`
	}
	if !decode(w, r, &input) {
		return
	}
	asset := Asset{rand.Text(), strings.TrimSpace(input.Name), input.Kind, strings.TrimSpace(input.Target), strings.TrimSpace(input.Owner), time.Now().UTC()}
	if err := validateAsset(asset); err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.assets) >= 200 {
		fail(w, 409, "Inventory limit of 200 assets reached")
		return
	}
	next := append(append([]Asset{}, s.assets...), asset)
	if err := saveAssets(s.file, next); err != nil {
		fail(w, 500, "Could not save inventory")
		return
	}
	s.assets = next
	send(w, 201, asset)
}
func (s *Server) removeAsset(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := []Asset{}
	found := false
	for _, asset := range s.assets {
		if asset.ID == r.PathValue("id") {
			found = true
		} else {
			next = append(next, asset)
		}
	}
	if !found {
		fail(w, 404, "Asset not found")
		return
	}
	if err := saveAssets(s.file, next); err != nil {
		fail(w, 500, "Could not save inventory")
		return
	}
	s.assets = next
	send(w, 200, map[string]bool{"removed": true})
}
func (s *Server) startRun(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Target     string `json:"target"`
		Kind       string `json:"kind"`
		Authorized bool   `json:"authorized"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !input.Authorized {
		fail(w, 400, "Confirm that you own or are authorized to check the target")
		return
	}
	if len(input.Target) == 0 || len(input.Target) > 1024 {
		fail(w, 400, "A target is required")
		return
	}
	target := input.Target
	if input.Kind == "source" {
		var err error
		target, err = s.sourceTarget(target)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
	} else if input.Kind != "website" && input.Kind != "api" && input.Kind != "backend" && input.Kind != "application" {
		fail(w, 400, "This asset category supports inventory only")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, run := range s.runs {
		if run.Status == "running" || run.Status == "cancelling" {
			fail(w, 409, "A check is already running; wait or cancel it first")
			return
		}
	}
	ctx, cancel := context.WithTimeout(s.context, 30*time.Second)
	run := &Run{ID: rand.Text(), Target: input.Target, Kind: input.Kind, Status: "running", StartedAt: time.Now().UTC(), Findings: []Finding{}, Checks: []webcheck.Check{}, Gaps: []string{}, cancel: cancel}
	s.runs = append([]*Run{run}, s.runs...)
	if len(s.runs) > 20 {
		s.runs = s.runs[:20]
	}
	go s.execute(ctx, run, target)
	send(w, 202, map[string]string{"id": run.ID})
}
func (s *Server) sourceTarget(target string) (string, error) {
	if filepath.IsAbs(target) {
		return "", fmt.Errorf("use a workspace-relative directory")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(s.root, target))
	if err != nil {
		return "", fmt.Errorf("directory does not exist")
	}
	rel, err := filepath.Rel(s.root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("directory must stay inside the configured workspace")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("target must be a directory")
	}
	return resolved, nil
}
func (s *Server) execute(ctx context.Context, run *Run, target string) {
	defer run.cancel()
	completed := Run{Status: "completed", Findings: []Finding{}, Checks: []webcheck.Check{}, Gaps: []string{}}
	if run.Kind == "source" {
		result, err := secrets.Scan(ctx, target, "dashboard", secrets.DefaultLimits())
		if err != nil {
			completed.Status = "failed"
			completed.Error = err.Error()
		} else {
			completed.Files = result.FilesScanned
			completed.Gaps = append(completed.Gaps, result.Summary.CoverageGaps...)
			if len(completed.Gaps) > 0 {
				completed.Status = "partial"
			}
			for _, f := range result.Findings {
				completed.Findings = append(completed.Findings, Finding{f.FindingId, f.Title, f.RuleId, strings.ToLower(strings.TrimPrefix(f.Severity.String(), "SEVERITY_")), f.Locations[0].ArtifactUri, f.Locations[0].GetStartLine(), f.Description})
			}
			completed.jsonReport, err = report.JSON(result)
			if err == nil {
				completed.sarifReport, err = report.SARIF(result)
			}
			if err != nil {
				completed.Status = "failed"
				completed.Error = "Report encoding failed"
			}
		}
	} else {
		checks, err := webcheck.Inspect(ctx, target, run.Kind)
		if err != nil {
			completed.Status = "failed"
			completed.Error = err.Error()
		} else {
			completed.Checks = checks
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || run.Status == "cancelling" {
		completed.Status = "cancelled"
	}
	now := time.Now().UTC()
	run.Status = completed.Status
	run.FinishedAt = &now
	run.Files = completed.Files
	run.Findings = completed.Findings
	run.FindingCount = len(completed.Findings)
	run.Checks = completed.Checks
	run.Gaps = completed.Gaps
	run.Error = completed.Error
	run.jsonReport = completed.jsonReport
	run.sarifReport = completed.sarifReport
}
func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, run := range s.runs {
		if run.ID == r.PathValue("id") {
			if run.Status == "running" {
				run.Status = "cancelling"
				run.cancel()
			}
			send(w, 200, map[string]string{"status": run.Status})
			return
		}
	}
	fail(w, 404, "Check not found")
}
func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	var snapshot *Run
	for _, run := range s.runs {
		if run.ID == r.PathValue("id") {
			copy := *run
			snapshot = &copy
			break
		}
	}
	s.mu.Unlock()
	if snapshot != nil {
		run := snapshot
		if run.Status == "running" || run.Status == "cancelling" {
			fail(w, 409, "Check has not finished")
			return
		}
		format := r.URL.Query().Get("format")
		if format != "json" && format != "sarif" {
			fail(w, 400, "Unsupported report format")
			return
		}
		data := run.jsonReport
		if format == "sarif" {
			data = run.sarifReport
		}
		if len(data) == 0 && format == "json" {
			var err error
			data, err = json.MarshalIndent(run, "", "  ")
			if err != nil {
				fail(w, 500, "Report encoding failed")
				return
			}
		}
		if len(data) == 0 {
			fail(w, 400, "SARIF is available for source scans only")
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=godseye-%s.%s", run.ID, format))
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}
	fail(w, 404, "Check not found")
}
