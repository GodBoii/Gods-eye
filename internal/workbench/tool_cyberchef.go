// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

const cyberChefMaxInput = 256 << 10

// auditCyberChef inspects supplied security data. It never treats decoded JWT
// claims as authenticated and never loads a key or fetches issuer metadata.
func auditCyberChef(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Target != "" || req.RunEngine {
		return nil, fmt.Errorf("CyberChef inspection accepts offline input only")
	}
	if len(req.Input) > (cyberChefMaxInput+2)/3*4 {
		return nil, fmt.Errorf("CyberChef input exceeds 256 KiB")
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > cyberChefMaxInput {
		return nil, fmt.Errorf("provide 1 to 256 KiB of JSON input")
	}
	fields, err := cyberChefObject(data)
	if err != nil {
		return nil, fmt.Errorf("invalid CyberChef JSON object")
	}
	for key := range fields {
		if key != "kind" && key != "value" && key != "expectedIssuer" && key != "expectedAudience" {
			return nil, fmt.Errorf("unsupported CyberChef input field")
		}
	}
	var kind, value, issuer, audience string
	for key, dest := range map[string]*string{"kind": &kind, "value": &value, "expectedIssuer": &issuer, "expectedAudience": &audience} {
		if raw, present := fields[key]; present {
			if string(raw) == "null" || json.Unmarshal(raw, dest) != nil {
				return nil, fmt.Errorf("CyberChef fields must be strings")
			}
		}
	}
	if value == "" {
		return nil, fmt.Errorf("provide a security data value")
	}
	r := newReport("cyberchef", "Offline security data inspection; input values are withheld from evidence.", data)
	r.Limited = true
	switch kind {
	case "jwt":
		err = cyberChefJWT(ctx, r, value, issuer, audience, time.Now())
	case "pem":
		if issuer != "" || audience != "" {
			return nil, fmt.Errorf("issuer and audience policies apply only to JWT inspection")
		}
		err = cyberChefPEM(ctx, r, value, time.Now())
	default:
		return nil, fmt.Errorf("choose jwt or pem inspection")
	}
	if err != nil {
		return nil, err
	}
	return r, ctx.Err()
}

// Reject duplicate top-level security fields and trailing JSON rather than
// silently accepting the last occurrence. Never include parser input in errors.
func cyberChefObject(data []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("expected object")
	}
	result := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid object")
		}
		key, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("invalid field")
		}
		if _, duplicate := result[key]; duplicate {
			return nil, fmt.Errorf("duplicate field")
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return nil, fmt.Errorf("invalid field value")
		}
		result[key] = raw
	}
	if _, err := d.Token(); err != nil {
		return nil, fmt.Errorf("invalid object end")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	return result, nil
}

func cyberChefJWT(ctx context.Context, r *Report, value, issuer, audience string, now time.Time) error {
	r.gap("JWT signature, issuer trust, key selection and server enforcement are not verified. Decoded claims are untrusted input; no keys or remote metadata are loaded.")
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("expected a three-part compact JWT")
	}
	decoded := make([][]byte, 3)
	for i, part := range parts {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, ch := range part {
			if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
				return fmt.Errorf("JWT segments require unpadded base64url")
			}
		}
		var err error
		decoded[i], err = base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil {
			return fmt.Errorf("invalid JWT base64url segment")
		}
	}
	header, err := cyberChefObject(decoded[0])
	if err != nil {
		return fmt.Errorf("invalid or ambiguous JWT header")
	}
	claims, err := cyberChefObject(decoded[1])
	if err != nil {
		return fmt.Errorf("invalid or ambiguous JWT claims")
	}
	var alg string
	if json.Unmarshal(header["alg"], &alg) != nil || alg == "" {
		return fmt.Errorf("JWT alg must be a nonempty string")
	}
	switch alg {
	case "none":
		r.finding("high", "JWT declares no signature algorithm", "JWT.header.alg", "Untrusted header declares alg none. Reject unsecured tokens in authenticated application flows; server acceptance has not been tested.")
		if len(decoded[2]) != 0 {
			return fmt.Errorf("unsecured JWT must have an empty signature")
		}
	case "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA":
		if len(decoded[2]) == 0 {
			return fmt.Errorf("signed JWT requires a signature segment")
		}
		r.observe("declared algorithm", "JWT.header.alg", alg+"; declaration only, signature unverified")
	default:
		r.finding("medium", "JWT algorithm outside inspection allowlist", "JWT.header.alg", "Algorithm is not recognized by this inspector. Configure an explicit verifier algorithm policy; cryptographic validity is unknown.")
	}
	if raw, exists := header["typ"]; exists {
		var typ string
		if string(raw) == "null" || json.Unmarshal(raw, &typ) != nil {
			return fmt.Errorf("JWT typ must be a string")
		}
		if typ != "JWT" && typ != "at+jwt" && typ != "application/at+jwt" {
			r.finding("low", "JWT type requires policy review", "JWT.header.typ", "Declared token type is outside the JWT/access-token types recognized by this inspector. Apply the expected application token type policy.")
		}
	}
	for _, key := range []string{"crit", "b64"} {
		if _, exists := header[key]; exists {
			r.finding("medium", "JWT extension requires verifier support", "JWT.header."+key, "A JWS extension is present. This inspector does not process critical or unencoded-payload extensions; verifier support must be checked.")
		}
	}
	for _, key := range []string{"jku", "x5u", "jwk", "x5c", "kid"} {
		if _, exists := header[key]; exists {
			r.observe("untrusted key selector", "JWT.header."+key, "Present; value withheld. The verifier must use trusted key selection policy. No reference was fetched or trusted.")
		}
	}
	dates := map[string]float64{}
	for _, key := range []string{"exp", "nbf", "iat"} {
		raw, exists := claims[key]
		if !exists {
			if key == "exp" {
				r.finding("low", "JWT expiration absent", "JWT.claims.exp", "Token contains no expiration claim. Review application lifetime policy; this alone does not establish server acceptance.")
			}
			continue
		}
		var n json.Number
		if len(raw) == 0 || raw[0] == '"' || json.Unmarshal(raw, &n) != nil {
			return fmt.Errorf("JWT time claims must be numeric dates")
		}
		x, err := n.Float64()
		if err != nil || math.IsNaN(x) || math.IsInf(x, 0) || x < -62135596800 || x > 253402300799 {
			return fmt.Errorf("JWT numeric date is unsupported")
		}
		dates[key] = x
		seconds := float64(now.UnixNano()) / 1e9
		if key == "exp" && x <= seconds {
			r.finding("medium", "JWT is expired by its claims", "JWT.claims.exp", "Unverified expiration is at or before inspection time. Check server expiration enforcement.")
		}
		if key == "nbf" && x > seconds {
			r.finding("medium", "JWT is not yet valid by its claims", "JWT.claims.nbf", "Unverified not-before is after inspection time; no clock tolerance is applied.")
		}
		if key == "iat" && x > seconds {
			r.finding("low", "JWT issued-at is in the future", "JWT.claims.iat", "Unverified issued-at is after inspection time; check issuer clocks and verifier policy.")
		}
	}
	if exp, exists := dates["exp"]; exists {
		for _, key := range []string{"nbf", "iat"} {
			if x, exists := dates[key]; exists && x >= exp {
				r.finding("medium", "JWT lifetime claims are inconsistent", "JWT.claims."+key, "Unverified not-before or issued-at is at or after expiration.")
			}
		}
	}
	var actualIssuer string
	if raw, exists := claims["iss"]; exists {
		if string(raw) == "null" || json.Unmarshal(raw, &actualIssuer) != nil {
			return fmt.Errorf("JWT issuer must be a string")
		}
	}
	if issuer != "" && issuer != actualIssuer {
		r.finding("medium", "JWT issuer policy mismatch", "JWT.claims.iss", "Unverified issuer is absent or differs from the supplied expected issuer. Values are withheld.")
	}
	audiences := []string{}
	if raw, exists := claims["aud"]; exists {
		var one string
		if string(raw) == "null" {
			return fmt.Errorf("JWT audience must be a string or string array")
		}
		if json.Unmarshal(raw, &one) == nil {
			audiences = append(audiences, one)
		} else {
			var items []json.RawMessage
			if json.Unmarshal(raw, &items) != nil {
				return fmt.Errorf("JWT audience must be a string or string array")
			}
			for _, item := range items {
				var entry string
				if string(item) == "null" || json.Unmarshal(item, &entry) != nil {
					return fmt.Errorf("JWT audience entries must be strings")
				}
				audiences = append(audiences, entry)
			}
		}
	}
	if audience != "" {
		match := false
		for _, a := range audiences {
			if a == audience {
				match = true
			}
		}
		if !match {
			r.finding("medium", "JWT audience policy mismatch", "JWT.claims.aud", "Unverified audience is absent or does not include the supplied expected audience. Values are withheld.")
		}
	}
	if issuer == "" || audience == "" {
		r.gap("Issuer and audience policies are checked only when expectedIssuer and expectedAudience are supplied.")
	}
	r.observe("inspection", "JWT", "Header and claims parsed; all claim values, token bytes and signature bytes withheld.")
	return ctx.Err()
}

func cyberChefPEM(ctx context.Context, r *Report, value string, now time.Time) error {
	if strings.Contains(value, "PRIVATE KEY") {
		return fmt.Errorf("private key material is not accepted; provide public certificates only")
	}
	r.gap("Certificate chain trust, hostname matching, revocation and deployment are not verified. Subject, issuer and SAN identity values are withheld.")
	remaining := []byte(value)
	count := 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining = bytes.TrimSpace(remaining)
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN ")) {
			return fmt.Errorf("PEM input contains unsupported surrounding data")
		}
		block, rest := pem.Decode(remaining)
		if block == nil {
			return fmt.Errorf("invalid PEM encoding")
		}
		if bytes.Count(remaining[:len(remaining)-len(rest)], []byte("-----BEGIN ")) != 1 {
			return fmt.Errorf("PEM input contains malformed or skipped blocks")
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return fmt.Errorf("private key material is not accepted; provide public certificates only")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fmt.Errorf("only public CERTIFICATE PEM blocks are accepted")
		}
		count++
		if count > 32 {
			return fmt.Errorf("provide at most 32 certificates")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("invalid X.509 certificate")
		}
		target := fmt.Sprintf("Certificate[%d]", count)
		r.observe("certificate fingerprint", target, "SHA-256 "+digest(cert.Raw))
		r.observe("certificate validity", target, cert.NotBefore.UTC().Format(time.RFC3339)+" to "+cert.NotAfter.UTC().Format(time.RFC3339))
		r.observe("certificate metadata", target, fmt.Sprintf("Version %d; CA %t; DNS SAN count %d; IP SAN count %d; signature %s", cert.Version, cert.IsCA, len(cert.DNSNames), len(cert.IPAddresses), cert.SignatureAlgorithm))
		if !now.Before(cert.NotAfter) {
			r.finding("high", "Certificate expired", target, "Certificate validity ended at or before inspection time.")
		} else if cert.NotAfter.Sub(now) <= 30*24*time.Hour {
			r.finding("low", "Certificate expires within 30 days", target, "Plan renewal and verify the deployed chain.")
		}
		if now.Before(cert.NotBefore) {
			r.finding("medium", "Certificate not yet valid", target, "Certificate validity begins after inspection time.")
		}
		switch cert.SignatureAlgorithm {
		case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
			r.finding("high", "Certificate uses a weak signature algorithm", target, "The declared certificate signature uses MD2, MD5 or SHA-1. Replace it with a supported modern signature.")
		case x509.UnknownSignatureAlgorithm:
			r.finding("medium", "Certificate signature algorithm unsupported", target, "This parser does not recognize the signature algorithm; cryptographic validity is unverified.")
		}
		switch key := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			r.observe("public key", target, fmt.Sprintf("RSA %d bits", key.N.BitLen()))
			if key.N.BitLen() < 2048 {
				r.finding("high", "Certificate RSA key below 2048 bits", target, "Replace the undersized RSA public key and corresponding certificate.")
			}
		case *ecdsa.PublicKey:
			r.observe("public key", target, fmt.Sprintf("ECDSA %d bits", key.Curve.Params().BitSize))
			if key.Curve.Params().BitSize < 256 {
				r.finding("medium", "Certificate EC key below 256 bits", target, "Review the elliptic-curve key against current application cryptographic policy.")
			}
		case ed25519.PublicKey:
			r.observe("public key", target, "Ed25519")
		default:
			r.observe("public key", target, "Algorithm outside RSA, ECDSA and Ed25519 inspection coverage")
		}
		remaining = rest
	}
	if count == 0 {
		return fmt.Errorf("provide at least one public certificate")
	}
	return ctx.Err()
}
