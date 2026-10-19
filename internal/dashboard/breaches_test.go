// SPDX-License-Identifier: Apache-2.0
package dashboard

import (
	"context"
	"testing"
)

func TestEmailBreachAPIBoundaries(t *testing.T) {
	app, err := New(context.Background(), t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler("127.0.0.1:8765", t.TempDir())
	for _, body := range []string{
		`{"email":"name@example.com","authorized":false}`,
		`{"email":"name@example.com"}`,
		`{"email":"a..b@example.com","authorized":true}`,
		`{"email":"name@example.com","authorized":true,"url":"https://evil.test/"}`,
		`{"email":"name@example.com","authorized":true} {}`,
	} {
		response := invoke(handler, "POST", "/api/lab/email-breaches", body)
		if response.Code != 400 {
			t.Fatalf("invalid boundary: %d %s", response.Code, response.Body.String())
		}
	}
	if len(app.evidence.List()) != 0 {
		t.Fatal("rejected requests produced saved reports")
	}
}
