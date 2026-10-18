// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type burpServer struct {
	URL string `json:"url"`
}
type burpParameter struct {
	Ref      string `json:"$ref"`
	Name     string `json:"name"`
	In       string `json:"in"`
	Required bool   `json:"required"`
}
type burpResponse struct {
	Ref     string                     `json:"$ref"`
	Content map[string]json.RawMessage `json:"content"`
}
type burpOperation struct {
	Parameters []burpParameter         `json:"parameters"`
	Responses  map[string]burpResponse `json:"responses"`
	Security   *[]map[string][]string  `json:"security"`
	Servers    []burpServer            `json:"servers"`
}
type burpSpec struct {
	OpenAPI  string                                `json:"openapi"`
	Paths    map[string]map[string]json.RawMessage `json:"paths"`
	Servers  []burpServer                          `json:"servers"`
	Security *[]map[string][]string                `json:"security"`
}
type burpHAR struct {
	Log *struct {
		Version string `json:"version"`
		Entries []struct {
			Request struct {
				Method string `json:"method"`
				URL    string `json:"url"`
			} `json:"request"`
			Response struct {
				Status  int `json:"status"`
				Content struct {
					MimeType string `json:"mimeType"`
				} `json:"content"`
				Headers []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
			} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}
type burpRoute struct {
	path, method string
	operation    burpOperation
	parameters   []burpParameter
	servers      []burpServer
}

// auditBurp reviews supplied API contracts against captured evidence. It never
// replays traffic and cannot establish authentication or authorization behavior.
func auditBurp(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.RunEngine {
		return nil, fmt.Errorf("Burp engine execution is unsupported; supply an OpenAPI/HAR contract bundle")
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	fields, err := burpEnvelope(data)
	if err != nil {
		return nil, err
	}
	var spec burpSpec
	var har burpHAR
	if json.Unmarshal(fields["spec"], &spec) != nil || json.Unmarshal(fields["har"], &har) != nil {
		return nil, fmt.Errorf("spec and har must be OpenAPI 3 and HAR 1.2 JSON objects")
	}
	if !strings.HasPrefix(spec.OpenAPI, "3.0.") && !strings.HasPrefix(spec.OpenAPI, "3.1.") {
		return nil, fmt.Errorf("spec requires OpenAPI 3.0 or 3.1")
	}
	if spec.Paths == nil || len(spec.Paths) > maxRecords || har.Log == nil || har.Log.Version != "1.2" || len(har.Log.Entries) == 0 || len(har.Log.Entries) > maxRecords {
		return nil, fmt.Errorf("require paths and HAR 1.2 with 1 to 1,000 entries; at most 1,000 paths")
	}
	scope := ""
	if req.Target != "" {
		u, err := burpURL(req.Target)
		if err != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return nil, fmt.Errorf("target must be an HTTP origin without path, query or fragment")
		}
		scope = burpOrigin(u)
	}
	r := newReport("burp-suite", "Offline API contract audit.", data)
	r.Limited = true
	r.gap("Offline contract evidence only; no Burp engine, active scanning, replay, schema/body validation or authorization verification. Undocumented endpoints are review candidates, not confirmed vulnerabilities.")
	r.gap("Query values, headers and bodies are not retained. Missing traffic is a coverage gap; a declared public operation is not a vulnerability. Unresolved references are not dereferenced.")
	routes, err := burpRoutes(ctx, spec, r)
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	checked, skipped := 0, 0
	for _, e := range har.Log.Entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		u, err := burpURL(e.Request.URL)
		method := strings.ToLower(e.Request.Method)
		if err != nil || !burpMethod(method) || e.Response.Status < 100 || e.Response.Status > 599 {
			return nil, fmt.Errorf("HAR entries require valid HTTP URLs, standard methods and status 100 to 599")
		}
		if scope != "" && scope != burpOrigin(u) {
			skipped++
			continue
		}
		query, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return nil, fmt.Errorf("HAR request has malformed query encoding")
		}
		checked++
		target := burpOrigin(u) + u.EscapedPath()
		matches := []int{}
		best := -1
		for i, route := range routes {
			if route.method != method {
				continue
			}
			for _, server := range route.servers {
				serverURL, err := burpURL(server.URL)
				if err != nil {
					continue
				}
				pattern := strings.TrimSuffix(serverURL.EscapedPath(), "/") + route.path
				if burpOrigin(serverURL) == burpOrigin(u) && burpPath(pattern, u.EscapedPath()) {
					score := burpSpecificity(pattern)
					if score > best {
						matches = []int{i}
						best = score
					} else if score == best {
						matches = append(matches, i)
					}
					break
				}
			}
		}
		if len(matches) != 1 {
			if len(matches) > 1 {
				r.gap("Ambiguous templated operation matches were excluded from contract checks.")
			} else {
				r.finding("info", "Captured endpoint outside resolved API contract", target, strings.ToUpper(method)+" did not match a resolved operation. Check spec completeness, server scope and endpoint ownership; this is not a vulnerability claim.")
			}
			continue
		}
		i := matches[0]
		seen[i] = true
		route := routes[i]
		label := strings.ToUpper(method) + " " + route.path
		security := route.operation.Security
		if security == nil {
			security = spec.Security
		}
		declaration := "security unspecified"
		if security != nil {
			declaration = "security required by declaration"
			if len(*security) == 0 {
				declaration = "public by declaration"
			}
			for _, alternative := range *security {
				if len(alternative) == 0 {
					declaration = "public alternative by declaration"
				}
			}
		}
		r.observe("API contract", target, fmt.Sprintf("%s; captured status=%d; %s; enforcement unverified", label, e.Response.Status, declaration))
		for _, p := range route.parameters {
			if p.Ref != "" {
				r.gap("Unresolved parameter references prevent complete required-query checks.")
				continue
			}
			if p.In == "query" && p.Required {
				if _, ok := query[p.Name]; !ok {
					r.finding("low", "Required query parameter absent", target, label+" lacks required query parameter "+p.Name+" in captured URL; values omitted.")
				}
			}
		}
		response, ok := route.operation.Responses[strconv.Itoa(e.Response.Status)]
		if !ok {
			response, ok = route.operation.Responses[strconv.Itoa(e.Response.Status/100)+"XX"]
		}
		if !ok {
			response, ok = route.operation.Responses["default"]
		}
		if !ok {
			r.finding("low", "Undocumented API response status", target, fmt.Sprintf("%s captured HTTP %d without a matching status, status range or default response.", label, e.Response.Status))
			continue
		}
		if response.Ref != "" {
			r.gap("Unresolved response references prevent response content-type validation.")
			continue
		}
		if len(response.Content) == 0 {
			continue
		}
		actual := e.Response.Content.MimeType
		for _, h := range e.Response.Headers {
			if strings.EqualFold(h.Name, "Content-Type") {
				actual = h.Value
				break
			}
		}
		mt, _, err := mime.ParseMediaType(actual)
		if err != nil {
			r.gap("Missing or malformed captured response content type prevents some comparisons.")
			continue
		}
		matched := false
		for expected := range response.Content {
			if burpMedia(expected, mt) {
				matched = true
				break
			}
		}
		if !matched {
			r.finding("low", "API response content-type mismatch", target, label+" captured a response media type outside the documented response content keys. Inspect original evidence; body validity is unverified.")
		}
	}
	r.observe("API coverage", "", fmt.Sprintf("%d captured entries checked; %d outside origin filter; %d/%d resolved operations observed.", checked, skipped, len(seen), len(routes)))
	if len(seen) < len(routes) {
		r.gap(fmt.Sprintf("%d resolved operations have no matching captured request; missing traffic is not evidence of secure behavior.", len(routes)-len(seen)))
	}
	r.Summary = fmt.Sprintf("Reviewed %d captured entries against %d resolved API operations; %d contract review candidates; enforcement unverified.", checked, len(routes), len(r.Findings))
	return r, nil
}

func burpEnvelope(data []byte) (map[string]json.RawMessage, error) {
	if len(data) == 0 || len(data) > MaxInput {
		return nil, fmt.Errorf("contract bundle must contain 1 byte to 8 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("expected spec/har JSON object")
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid contract bundle")
		}
		key, ok := token.(string)
		if !ok || (key != "spec" && key != "har") || fields[key] != nil {
			return nil, fmt.Errorf("unknown or duplicate contract bundle field")
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil || len(raw) == 0 || raw[0] != '{' {
			return nil, fmt.Errorf("spec and har must be objects")
		}
		fields[key] = raw
	}
	if _, err := d.Token(); err != nil {
		return nil, fmt.Errorf("invalid contract bundle")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing contract data")
	}
	if fields["spec"] == nil || fields["har"] == nil {
		return nil, fmt.Errorf("spec and har are required")
	}
	return fields, nil
}

func burpRoutes(ctx context.Context, spec burpSpec, r *Report) ([]burpRoute, error) {
	routes := []burpRoute{}
	paths := make([]string, 0, len(spec.Paths))
	for p := range spec.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	operations := 0
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#") || len(p) > 512 {
			return nil, fmt.Errorf("API paths must be absolute paths without query or fragment, at most 512 bytes")
		}
		item := spec.Paths[p]
		if item == nil {
			return nil, fmt.Errorf("path items must be objects")
		}
		if _, ok := item["$ref"]; ok {
			r.gap("Unresolved path-item references prevent complete endpoint comparison.")
		}
		var parameters []burpParameter
		if raw, ok := item["parameters"]; ok {
			if json.Unmarshal(raw, &parameters) != nil {
				return nil, fmt.Errorf("invalid path parameters")
			}
		}
		servers := spec.Servers
		if raw, ok := item["servers"]; ok {
			if json.Unmarshal(raw, &servers) != nil {
				return nil, fmt.Errorf("invalid path servers")
			}
		}
		for _, method := range []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"} {
			raw, ok := item[method]
			if !ok {
				continue
			}
			operations++
			if operations > maxRecords {
				return nil, fmt.Errorf("API exceeds 1,000 operations")
			}
			var op burpOperation
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &op) != nil || len(op.Responses) == 0 {
				return nil, fmt.Errorf("API operations require an object with responses")
			}
			s := servers
			if len(op.Servers) > 0 {
				s = op.Servers
			}
			if len(s) > maxRecords || len(parameters)+len(op.Parameters) > maxRecords || len(op.Responses) > maxRecords {
				return nil, fmt.Errorf("operation servers, parameters and responses are limited to 1,000 records")
			}
			resolved := []burpServer{}
			for _, server := range s {
				u, err := burpURL(server.URL)
				if err != nil || strings.ContainsAny(server.URL, "{}") || u.RawQuery != "" || u.Fragment != "" {
					r.gap("Missing, relative or variable server URLs are unresolved; supply explicit absolute API server URLs for comparison.")
					continue
				}
				resolved = append(resolved, server)
			}
			if len(resolved) == 0 {
				r.gap("Operations without resolved absolute servers cannot be matched reliably.")
				continue
			}
			merged := append([]burpParameter(nil), parameters...)
			for _, parameter := range op.Parameters {
				replaced := false
				for i, existing := range merged {
					if parameter.Ref == "" && existing.Name == parameter.Name && existing.In == parameter.In {
						merged[i] = parameter
						replaced = true
						break
					}
				}
				if !replaced {
					merged = append(merged, parameter)
				}
			}
			for _, parameter := range merged {
				if parameter.Ref == "" && (parameter.Name == "" || (parameter.In != "query" && parameter.In != "path" && parameter.In != "header" && parameter.In != "cookie")) {
					return nil, fmt.Errorf("API parameters require a name and a supported location")
				}
			}
			routes = append(routes, burpRoute{p, method, op, merged, resolved})
		}
	}
	return routes, nil
}
func burpURL(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || len(u.EscapedPath()) > 512 {
		return nil, fmt.Errorf("invalid HTTP URL")
	}
	return u, nil
}
func burpOrigin(u *url.URL) string {
	host := strings.ToLower(u.Host)
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		host = strings.ToLower(u.Hostname())
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	return u.Scheme + "://" + host
}
func burpMethod(s string) bool {
	return s == "get" || s == "post" || s == "put" || s == "patch" || s == "delete" || s == "options" || s == "head" || s == "trace"
}
func burpPath(pattern, path string) bool {
	a, b := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.HasPrefix(a[i], "{") && strings.HasSuffix(a[i], "}") && len(a[i]) > 2 {
			if b[i] == "" {
				return false
			}
			continue
		}
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func burpSpecificity(path string) int {
	score := 0
	for _, part := range strings.Split(path, "/") {
		if !(strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}")) {
			score++
		}
	}
	return score
}
func burpMedia(pattern, actual string) bool {
	p := strings.Split(strings.ToLower(pattern), "/")
	a := strings.Split(strings.ToLower(actual), "/")
	return len(p) == 2 && len(a) == 2 && (p[0] == "*" || p[0] == a[0]) && (p[1] == "*" || p[1] == a[1])
}
