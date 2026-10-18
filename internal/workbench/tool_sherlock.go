// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

type sherlockProfile struct {
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Title      string `json:"title"`
	Canonical  string `json:"canonical"`
	ObservedAt string `json:"observedAt"`
}

// auditSherlock reviews explicitly supplied observations. It never enumerates
// platforms, fetches profiles or infers a person's identity from response data.
func auditSherlock(ctx context.Context, req ToolRequest) (*Report, error) {
	if req.RunEngine || req.Target != "" {
		return nil, fmt.Errorf("profile evidence review accepts offline JSON only; live lookup and engine execution are unsupported")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > 256<<10 {
		return nil, fmt.Errorf("profile evidence requires nonempty JSON up to 256 KiB")
	}
	var input struct {
		Username string            `json:"username"`
		Profiles []sherlockProfile `json:"profiles"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("expected one JSON object containing username and profiles only")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`).MatchString(input.Username) {
		return nil, fmt.Errorf("username must contain 1-64 ASCII letters, digits, periods, underscores or hyphens, starting with a letter or digit")
	}
	if len(input.Profiles) < 1 || len(input.Profiles) > 32 {
		return nil, fmt.Errorf("provide 1-32 explicit profile observations")
	}
	now := time.Now().UTC()
	r := newReport("sherlock", "Offline profile response evidence reviewed.", nil)
	r.Limited = true
	seen := make(map[string]bool)
	for i, profile := range input.Profiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		target := fmt.Sprintf("profile-record-%02d", i+1)
		u, err := sherlockProfileURL(profile.URL)
		if err != nil {
			return nil, fmt.Errorf("profile record %d: invalid HTTPS profile URL", i+1)
		}
		if profile.Status < 200 || profile.Status > 599 || len(profile.Title) > 2048 {
			return nil, fmt.Errorf("profile record %d requires status 200-599 and title up to 2048 bytes", i+1)
		}
		observed, err := time.Parse(time.RFC3339, profile.ObservedAt)
		if err != nil || observed.Year() < 2000 || observed.After(now.Add(5*time.Minute)) {
			return nil, fmt.Errorf("profile record %d requires an RFC3339 observation timestamp from 2000 onward, no more than five minutes in the future", i+1)
		}
		if seen[u.String()] {
			r.finding("info", "Repeated profile observation", target, "This URL repeats an earlier supplied observation. Repeated records are not independent account evidence.")
		}
		seen[u.String()] = true
		if !strings.EqualFold(path.Base(strings.TrimRight(u.Path, "/")), input.Username) {
			r.finding("info", "Profile path differs from supplied username", target, "The final URL path segment does not match the supplied username. Platform URL conventions vary; review the supplied evidence manually.")
		}
		if profile.Canonical != "" {
			canonical, err := sherlockProfileURL(profile.Canonical)
			if err != nil {
				return nil, fmt.Errorf("profile record %d: invalid HTTPS canonical URL", i+1)
			}
			if !strings.EqualFold(canonical.Host, u.Host) || strings.TrimRight(canonical.EscapedPath(), "/") != strings.TrimRight(u.EscapedPath(), "/") {
				r.finding("info", "Canonical URL differs from profile URL", target, "The supplied canonical points to a different host or path. This may indicate a login page, redirect destination, generic error page or normal alias. No destination was fetched.")
			}
		}
		state := "successful response; account existence remains unverified"
		switch {
		case profile.Status >= 500:
			state = "server failure; account existence remains unknown"
		case profile.Status == 404 || profile.Status == 410:
			state = "missing resource response; account existence remains unknown"
		case profile.Status == 401 || profile.Status == 403 || profile.Status == 429:
			state = "access blocked or rate limited; account existence remains unknown"
		case profile.Status >= 400:
			state = "client error response; account existence remains unknown"
		case profile.Status >= 300:
			state = "redirect response; destination was not verified"
		}
		title := strings.ToLower(strings.Join(strings.Fields(profile.Title), " "))
		if profile.Status >= 200 && profile.Status < 300 && (strings.Contains(title, "page not found") || strings.Contains(title, "profile not found") || strings.Contains(title, "user not found") || strings.Contains(title, "404 not found")) {
			r.finding("info", "Possible soft 404 response", target, "Successful status conflicts with a missing-page title signature. The supplied title is omitted. Review platform-specific behavior; this is not proof an account is absent.")
			state = "successful status with missing-page title signal; account existence remains unknown"
		}
		if now.Sub(observed) > 30*24*time.Hour {
			r.finding("info", "Stale profile observation", target, "The supplied response observation is over 30 days old. Recollect authorized evidence before relying on current response state.")
		}
		r.observe("supplied response state", target, fmt.Sprintf("HTTP %d; %s; observed %s", profile.Status, state, observed.UTC().Format(time.RFC3339)))
	}
	r.gap("Caller-supplied offline observations are not independently verified. No platform enumeration, network requests, account existence claims or identity matching runs. HTTP 200 does not establish an account exists.")
	r.gap("Titles, URLs and usernames are not retained in this report. No names, email addresses or profile contents are extracted. Title signatures are heuristic and platform-specific soft errors may be missed.")
	r.Summary = fmt.Sprintf("Reviewed %d supplied profile observations; %d evidence quality review items. Account existence and identity remain unverified.", len(input.Profiles), len(r.Findings))
	return r, nil
}

func sherlockProfileURL(value string) (*url.URL, error) {
	u, err := validateAuditURL(value)
	if err != nil || u.Scheme != "https" || u.RawQuery != "" || u.ForceQuery || strings.ContainsAny(u.Path, "@\\\r\n\x00") {
		return nil, fmt.Errorf("expected HTTPS URL without query, credentials, fragment or email-like path")
	}
	return u, nil
}
