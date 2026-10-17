// SPDX-License-Identifier: Apache-2.0
package world

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type rejectNetwork struct{ calls atomic.Int32 }

func (r *rejectNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls.Add(1)
	return nil, context.Canceled
}

func TestFreshCacheSurvivesServiceRestart(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	expires := now.Add(time.Minute)
	initial := newService(directory, &http.Client{}, func() time.Time { return now })
	saved := Snapshot{ID: "earthquakes", Source: "USGS earthquakes", SourceURL: initial.feeds["earthquakes"].url, Status: "fresh", FetchedAt: &now, ExpiresAt: &expires, Body: `{"features":[]}`}
	if err := initial.save("earthquakes", saved); err != nil {
		t.Fatal(err)
	}
	transport := &rejectNetwork{}
	restarted := newService(directory, &http.Client{Transport: transport}, func() time.Time { return now.Add(10 * time.Second) })
	result, _ := restarted.Snapshot(context.Background(), "earthquakes")
	if result.Status != "fresh" || result.Body != saved.Body || transport.calls.Load() != 0 {
		t.Fatal("fresh persisted data was fetched again or lost")
	}
}

func TestFeedCachingAndStaleFailures(t *testing.T) {
	var calls atomic.Int32
	var failed atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if failed.Load() {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte(`{"features":[]}`))
	}))
	defer upstream.Close()
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	service := newService(t.TempDir(), upstream.Client(), clock)
	service.feeds["earthquakes"].url = upstream.URL
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			snapshot, ok := service.Snapshot(context.Background(), "earthquakes")
			if !ok || snapshot.Status != "fresh" {
				t.Error("missing fresh snapshot")
			}
		}()
	}
	workers.Wait()
	if calls.Load() != 1 {
		t.Fatal("requests were not coalesced", calls.Load())
	}
	failed.Store(true)
	now = now.Add(2 * time.Minute)
	stale, _ := service.Snapshot(context.Background(), "earthquakes")
	if stale.Status != "stale" || stale.Body == "" || stale.FetchedAt == nil || stale.Error == "" {
		t.Fatal("last good data was not preserved with its age")
	}
	service.Snapshot(context.Background(), "earthquakes")
	if calls.Load() != 2 {
		t.Fatal("provider failure cooldown was ignored")
	}
	if _, ok := service.Snapshot(context.Background(), "http://untrusted.example"); ok {
		t.Fatal("accepted arbitrary upstream URL")
	}
}

func TestInvalidAndRedirectedFeeds(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
	}{{"html", "<html>error</html>", 200}, {"oversized", string(make([]byte, maxFeedBytes+1)), 200}, {"redirect", "", 302}} {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "http://127.0.0.1/")
				w.WriteHeader(test.status)
				w.Write([]byte(test.body))
			}))
			defer upstream.Close()
			client := upstream.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			service := newService(t.TempDir(), client, time.Now)
			service.feeds["earthquakes"].url = upstream.URL
			snapshot, _ := service.Snapshot(context.Background(), "earthquakes")
			if snapshot.Status != "unavailable" || snapshot.Body != "" {
				t.Fatal("invalid feed accepted")
			}
		})
	}
}
