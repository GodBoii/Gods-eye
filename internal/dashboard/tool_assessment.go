// SPDX-License-Identifier: Apache-2.0
package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"godseye/internal/workbench"
)

func (s *Server) registerToolAssessments(mux *http.ServeMux) {
	capacity := make(chan struct{}, 2)
	mux.HandleFunc("GET /api/lab/capabilities", func(w http.ResponseWriter, r *http.Request) { send(w, 200, workbench.ToolCapabilities()) })
	mux.HandleFunc("POST /api/lab/assess", func(w http.ResponseWriter, r *http.Request) {
		select {
		case capacity <- struct{}{}:
			defer func() { <-capacity }()
		default:
			fail(w, 429, "Two tool assessments are already running")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, workbench.MaxInput+(64<<10))
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var request workbench.ToolRequest
		if err := decoder.Decode(&request); err != nil {
			fail(w, 400, "Invalid or oversized tool assessment request")
			return
		}
		if decoder.Decode(new(any)) != io.EOF {
			fail(w, 400, "Expected one JSON request")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		report, err := workbench.AuditTool(ctx, request)
		s.saveEvidence(w, report, err)
	})
}
