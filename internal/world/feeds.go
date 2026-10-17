// SPDX-License-Identifier: Apache-2.0
package world

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"
)

const maxFeedBytes = 2 << 20

type Snapshot struct {
	ID        string     `json:"id"`
	Source    string     `json:"source"`
	SourceURL string     `json:"sourceUrl"`
	Status    string     `json:"status"`
	FetchedAt *time.Time `json:"fetchedAt"`
	ExpiresAt *time.Time `json:"expiresAt"`
	Body      string     `json:"body"`
	Error     string     `json:"error"`
}

type feed struct {
	mu      sync.Mutex
	name    string
	url     string
	ttl     time.Duration
	json    bool
	last    Snapshot
	retryAt time.Time
}

type Service struct {
	feeds     map[string]*feed
	client    *http.Client
	directory string
	now       func() time.Time
}

// Only these fixed public data endpoints are reachable; no user-supplied URL is accepted.
func New(directory string) *Service {
	client := &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return newService(directory, client, time.Now)
}

func newService(directory string, client *http.Client, now func() time.Time) *Service {
	service := &Service{client: client, directory: directory, now: now, feeds: map[string]*feed{
		"earthquakes": {name: "USGS earthquakes", url: "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.geojson", ttl: time.Minute, json: true},
		"events":      {name: "NASA EONET", url: "https://eonet.gsfc.nasa.gov/api/v3/events?status=open&days=30&limit=100", ttl: 10 * time.Minute, json: true},
		"satellites":  {name: "CelesTrak space stations", url: "https://celestrak.org/NORAD/elements/gp.php?GROUP=stations&FORMAT=tle", ttl: 2 * time.Hour},
		"aircraft":    {name: "ADSB.lol regional aircraft (ODbL)", url: "https://api.adsb.lol/v2/point/20/79/250", ttl: 30 * time.Second, json: true},
	}}
	for id, entry := range service.feeds {
		entry.last = Snapshot{ID: id, Source: entry.name, SourceURL: entry.url, Status: "unavailable"}
		input, err := os.Open(filepath.Join(directory, id+".json"))
		if err != nil {
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(input, maxFeedBytes*3+1))
		input.Close()
		var saved Snapshot
		if readErr == nil && len(data) <= maxFeedBytes*3 && json.Unmarshal(data, &saved) == nil && saved.ID == id && saved.SourceURL == entry.url && saved.FetchedAt != nil && saved.ExpiresAt != nil && validBody(entry, saved.Body) {
			entry.last = saved
		}
	}
	return service
}

func validBody(entry *feed, body string) bool {
	if len(body) == 0 || len(body) > maxFeedBytes || !utf8.ValidString(body) {
		return false
	}
	if entry.json {
		return json.Valid([]byte(body))
	}
	// Reject HTML/error pages before treating a response as an orbital catalog.
	return len(body) > 100 && containsTLE(body)
}

func containsTLE(body string) bool {
	for index := 0; index+3 < len(body); index++ {
		if (index == 0 || body[index-1] == '\n') && body[index] == '1' && body[index+1] == ' ' {
			return true
		}
	}
	return false
}

// Snapshot coalesces concurrent acquisitions per layer. Failures retain dated last-good data.
func (s *Service) Snapshot(ctx context.Context, id string) (Snapshot, bool) {
	entry, exists := s.feeds[id]
	if !exists {
		return Snapshot{}, false
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	now := s.now().UTC()
	if entry.last.ExpiresAt != nil && now.Before(*entry.last.ExpiresAt) {
		result := entry.last
		result.Status = "fresh"
		result.Error = ""
		return result, true
	}
	if now.Before(entry.retryAt) {
		return entry.last, true
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, entry.url, nil)
	if err == nil {
		req.Header.Set("User-Agent", "GodsEye/0.3 public-data-viewer")
		req.Header.Set("Accept", "application/json, text/plain;q=0.9")
	}
	var body []byte
	if err == nil {
		var response *http.Response
		response, err = s.client.Do(req)
		if err == nil {
			if response.StatusCode != http.StatusOK {
				err = fmt.Errorf("Provider returned HTTP %d", response.StatusCode)
			} else {
				body, err = io.ReadAll(io.LimitReader(response.Body, maxFeedBytes+1))
				if err == nil && !validBody(entry, string(body)) {
					err = fmt.Errorf("Provider returned an invalid or oversized feed")
				}
			}
			response.Body.Close()
		}
	}
	if err != nil {
		entry.last.Status = "unavailable"
		if entry.last.Body != "" {
			entry.last.Status = "stale"
		}
		entry.last.Error = "Feed acquisition failed. Retry after the provider cooldown."
		if ctx.Err() == nil {
			entry.retryAt = now.Add(time.Minute)
		}
		return entry.last, true
	}
	expires := now.Add(entry.ttl)
	entry.last = Snapshot{ID: id, Source: entry.name, SourceURL: entry.url, Status: "fresh", FetchedAt: &now, ExpiresAt: &expires, Body: string(body)}
	if err := s.save(id, entry.last); err != nil {
		entry.last.Error = "Live data loaded, but its local cache could not be saved."
	}
	return entry.last, true
}

func (s *Service) save(id string, snapshot Snapshot) error {
	if err := os.MkdirAll(s.directory, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(s.directory, "feed-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(s.directory, id+".json"))
}
