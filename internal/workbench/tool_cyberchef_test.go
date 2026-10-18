// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func cyberToken(header, claims string, signature []byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func cyberRun(t *testing.T, kind, value string, policy map[string]string) *Report {
	t.Helper()
	input := map[string]string{"kind": kind, "value": value}
	for key, value := range policy {
		input[key] = value
	}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	r, err := auditCyberChef(context.Background(), ToolRequest{Input: string(data)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Tool != "cyberchef" || r.InputSHA256 != digest(data) || !r.Limited {
		t.Fatal("missing report identity or honest coverage limitation")
	}
	return r
}

func cyberHas(r *Report, title string) bool {
	for _, f := range r.Findings {
		if f.Title == title {
			return true
		}
	}
	return false
}

func TestCyberChefJWTPolicyAndRedaction(t *testing.T) {
	token := cyberToken(`{"alg":"HS256","typ":"JWT","kid":"secret-key-selector"}`, `{"exp":1,"nbf":2,"iat":4102444800,"iss":"secret-issuer","aud":["secret-audience"],"sub":"secret-subject","custom":"secret-claim"}`, []byte("secret-signature"))
	r := cyberRun(t, "jwt", token, map[string]string{"expectedIssuer": "expected-secret-issuer", "expectedAudience": "expected-secret-audience"})
	for _, title := range []string{"JWT is expired by its claims", "JWT issued-at is in the future", "JWT lifetime claims are inconsistent", "JWT issuer policy mismatch", "JWT audience policy mismatch"} {
		if !cyberHas(r, title) {
			t.Errorf("missing %s", title)
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{token, "secret-key-selector", "secret-issuer", "secret-audience", "secret-subject", "secret-claim", "secret-signature"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("secret retained: %s", secret)
		}
	}
	if !strings.Contains(strings.Join(r.Gaps, " "), "not verified") {
		t.Fatal("signature/trust gap absent")
	}
}

func TestCyberChefJWTMatchingPolicy(t *testing.T) {
	token := cyberToken(`{"alg":"RS256","typ":"at+jwt"}`, `{"exp":4102444800,"nbf":1,"iat":1,"iss":"issuer","aud":["other","audience"]}`, []byte{1})
	r := cyberRun(t, "jwt", token, map[string]string{"expectedIssuer": "issuer", "expectedAudience": "audience"})
	if len(r.Findings) != 0 {
		t.Fatalf("unexpected findings: %+v", r.Findings)
	}
	// A nonempty arbitrary signature never produces a cryptographic success claim.
	for _, o := range r.Observations {
		if strings.Contains(o.Value, "verified") && !strings.Contains(o.Value, "unverified") {
			t.Fatal("false verification claim")
		}
	}
}

func TestCyberChefJWTNoneAndExtensions(t *testing.T) {
	r := cyberRun(t, "jwt", cyberToken(`{"alg":"none","crit":["custom"]}`, `{}`, nil), nil)
	for _, title := range []string{"JWT declares no signature algorithm", "JWT expiration absent", "JWT extension requires verifier support"} {
		if !cyberHas(r, title) {
			t.Errorf("missing %s", title)
		}
	}
}

func TestCyberChefRejectsAmbiguousJWT(t *testing.T) {
	cases := []struct {
		header, claims string
		signature      []byte
	}{
		{`{"alg":"HS256","alg":"none"}`, `{}`, nil},
		{`{"alg":"HS256"}`, `{"exp":1,"exp":4102444800}`, []byte{1}},
		{`{"alg":"HS256"}`, `{"exp":"1"}`, []byte{1}},
		{`{"alg":"HS256"}`, `{"exp":null}`, []byte{1}},
		{`{"alg":"HS256"}`, `{"exp":1e999}`, []byte{1}},
		{`{"alg":"HS256"}`, `{"aud":[null]}`, []byte{1}},
		{`{"alg":"HS256"}`, `{"aud":[1]}`, []byte{1}},
		{`{"alg":"HS256"}`, `{"iss":null}`, []byte{1}},
		{`{"alg":"HS256"}`, `{"typ":null}`, nil},
		{`{"alg":"none"}`, `{}`, []byte{1}},
		{`{"alg":"HS256"}`, `[]`, []byte{1}},
		{`{"alg":"HS256"} {}`, `{}`, []byte{1}},
	}
	for i, tc := range cases {
		input, err := json.Marshal(map[string]string{"kind": "jwt", "value": cyberToken(tc.header, tc.claims, tc.signature)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := auditCyberChef(context.Background(), ToolRequest{Input: string(input)}); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	for _, token := range []string{"a.b", "e30=.e30.", "e30.e30+.x", "e30.e30.AB", "e30.e30.\n"} {
		input, err := json.Marshal(map[string]string{"kind": "jwt", "value": token})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := auditCyberChef(context.Background(), ToolRequest{Input: string(input)}); err == nil {
			t.Errorf("malformed token accepted")
		}
	}
}

func cyberCertificate(t *testing.T, weak bool, before, after time.Time) string {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "secret-cert-name"}, DNSNames: []string{"secret-cert-name"}, NotBefore: before, NotAfter: after}
	var der []byte
	var err error
	if weak {
		key, keyErr := rsa.GenerateKey(rand.Reader, 1024)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		template.SignatureAlgorithm = x509.SHA1WithRSA
		der, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	} else {
		pub, key, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		der, err = x509.CreateCertificate(rand.Reader, template, template, pub, key)
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCyberChefPEMCertificateReview(t *testing.T) {
	now := time.Now()
	value := cyberCertificate(t, true, now.Add(-48*time.Hour), now.Add(-time.Hour))
	r := cyberRun(t, "pem", value, nil)
	for _, title := range []string{"Certificate expired", "Certificate uses a weak signature algorithm", "Certificate RSA key below 2048 bits"} {
		if !cyberHas(r, title) {
			t.Errorf("missing %s", title)
		}
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-cert-name") || strings.Contains(string(data), "BEGIN CERTIFICATE") {
		t.Fatal("certificate identity or raw material retained")
	}
	if !strings.Contains(strings.Join(r.Gaps, " "), "trust") {
		t.Fatal("missing trust limitation")
	}
}

func TestCyberChefPEMValidityAndBundle(t *testing.T) {
	now := time.Now()
	value := cyberCertificate(t, false, now.Add(time.Hour), now.Add(10*24*time.Hour))
	r := cyberRun(t, "pem", value+value, nil)
	if !cyberHas(r, "Certificate not yet valid") || !cyberHas(r, "Certificate expires within 30 days") {
		t.Fatalf("missing validity review: %+v", r.Findings)
	}
	if len(r.Findings) != 4 {
		t.Fatal("certificate locations not retained")
	}
	for _, value := range []string{value + "trailing", "prefix" + value, strings.Repeat(value, 33), "-----BEGIN CERTIFICATE-----\nbroken\n-----END CERTIFICATE-----\n" + value, value + "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}}))} {
		input, err := json.Marshal(map[string]string{"kind": "pem", "value": value})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := auditCyberChef(context.Background(), ToolRequest{Input: string(input)}); err == nil {
			t.Fatal("invalid or private PEM accepted")
		}
	}
}

func TestCyberChefInputBoundsAndCancellation(t *testing.T) {
	for _, input := range []string{"", `{"kind":"jwt","kind":"pem","value":"secret"}`, `{"kind":null,"value":"secret"}`, `{"kind":"pem","value":null}`, `{"kind":"other","value":"secret"}`, `{"kind":"jwt","value":"secret","extra":"secret"}`, `{"kind":"jwt","value":"secret"} {}`, strings.Repeat(" ", cyberChefMaxInput+1)} {
		if _, err := auditCyberChef(context.Background(), ToolRequest{Input: input}); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	for _, req := range []ToolRequest{{Target: "example.test"}, {RunEngine: true}, {Input: "eA==", Encoding: "bad"}} {
		if _, err := auditCyberChef(context.Background(), req); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditCyberChef(ctx, ToolRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not respected")
	}
}
