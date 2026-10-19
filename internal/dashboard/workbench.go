// SPDX-License-Identifier: Apache-2.0
package dashboard

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"godseye/internal/workbench"
)

// Workbench requests use the parent dashboard's Host, Origin and custom-header
// protections. At most two bounded operations can occupy handlers at once.
func (s *Server) registerWorkbench(mux *http.ServeMux) {
	breaches := workbench.NewBreachChecker()
	capacity := make(chan struct{}, 2)
	bounded := func(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			select {
			case capacity <- struct{}{}:
				defer func() { <-capacity }()
			default:
				fail(w, 429, "Two workbench operations are already running")
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
			defer cancel()
			next(w, r.WithContext(ctx))
		}
	}
	mux.HandleFunc("GET /api/lab/catalog", func(w http.ResponseWriter, r *http.Request) {
		send(w, 200, map[string]any{"tools": workbench.Catalog(), "formats": workbench.Formats(), "maxInputBytes": workbench.MaxInput})
	})
	mux.HandleFunc("GET /api/lab/reports", func(w http.ResponseWriter, r *http.Request) { send(w, 200, s.evidence.List()) })
	mux.HandleFunc("GET /api/lab/reports/{id}", func(w http.ResponseWriter, r *http.Request) {
		report := s.evidence.Get(r.PathValue("id"))
		if report == nil {
			fail(w, 404, "Evidence report not found")
			return
		}
		if r.URL.Query().Get("download") == "1" {
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=godseye-evidence-%s.json", report.ID))
		}
		send(w, 200, report)
	})
	mux.HandleFunc("POST /api/lab/import", bounded(func(w http.ResponseWriter, r *http.Request) {
		data, ok := readEvidence(w, r)
		if !ok {
			return
		}
		report, err := workbench.Import(r.URL.Query().Get("format"), data)
		s.saveEvidence(w, report, err)
	}))
	mux.HandleFunc("POST /api/lab/file", bounded(func(w http.ResponseWriter, r *http.Request) {
		data, ok := readEvidence(w, r)
		if !ok {
			return
		}
		var report *workbench.Report
		var err error
		switch r.URL.Query().Get("mode") {
		case "file":
			report, err = workbench.InspectFile(data)
		case "pcap":
			report, err = workbench.InspectCapture(data)
		case "iam":
			report, err = workbench.IAM(data)
		default:
			fail(w, 400, "Choose file, pcap or iam analysis")
			return
		}
		s.saveEvidence(w, report, err)
	}))
	mux.HandleFunc("POST /api/lab/diagnose", bounded(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Mode       string `json:"mode"`
			Target     string `json:"target"`
			Ports      []int  `json:"ports"`
			Authorized bool   `json:"authorized"`
		}
		if !decode(w, r, &input) {
			return
		}
		if !input.Authorized {
			fail(w, 400, "Confirm ownership or authorization for this target")
			return
		}
		var report *workbench.Report
		var err error
		switch input.Mode {
		case "tcp":
			report, err = workbench.TCP(r.Context(), input.Target, input.Ports)
		case "dns":
			report, err = workbench.DNS(r.Context(), input.Target)
		default:
			fail(w, 400, "Choose tcp or dns diagnostics")
			return
		}
		s.saveEvidence(w, report, err)
	}))
	mux.HandleFunc("POST /api/lab/email-breaches", bounded(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Email      string `json:"email"`
			Authorized bool   `json:"authorized"`
		}
		if !decode(w, r, &input) {
			return
		}
		if !input.Authorized {
			fail(w, 400, "Confirm permission to send this email address to XposedOrNot")
			return
		}
		report, err := breaches.Check(r.Context(), input.Email)
		s.saveEvidence(w, report, err)
	}))
}

func readEvidence(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, workbench.MaxInput)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		fail(w, 413, "Could not read input within the 8 MiB limit")
		return nil, false
	}
	if len(data) == 0 {
		fail(w, 400, "Select a non-empty file")
		return nil, false
	}
	return data, true
}

func (s *Server) saveEvidence(w http.ResponseWriter, report *workbench.Report, err error) {
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err := s.evidence.Save(report); err != nil {
		fail(w, 500, "Could not persist normalized evidence")
		return
	}
	send(w, 201, report)
}
