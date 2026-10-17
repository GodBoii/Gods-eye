// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

func stringList(raw json.RawMessage) ([]string, error) {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return []string{single}, nil
	}
	var multiple []string
	if json.Unmarshal(raw, &multiple) == nil && len(multiple) > 0 {
		return multiple, nil
	}
	return nil, fmt.Errorf("expected a non-empty string or string array")
}

func IAM(data []byte) (*Report, error) {
	if err := checkInput(data); err != nil {
		return nil, err
	}
	type statement struct {
		SID       string                     `json:"Sid"`
		Effect    string                     `json:"Effect"`
		Action    json.RawMessage            `json:"Action"`
		NotAction json.RawMessage            `json:"NotAction"`
		Resource  json.RawMessage            `json:"Resource"`
		Principal json.RawMessage            `json:"Principal"`
		Condition map[string]json.RawMessage `json:"Condition"`
	}
	var doc struct {
		Statements json.RawMessage `json:"Statement"`
	}
	if err := decodeJSON(data, &doc); err != nil {
		return nil, err
	}
	var entries []statement
	if bytes.HasPrefix(bytes.TrimSpace(doc.Statements), []byte("[")) {
		if err := json.Unmarshal(doc.Statements, &entries); err != nil {
			return nil, fmt.Errorf("invalid policy statements")
		}
	} else {
		var single statement
		if err := json.Unmarshal(doc.Statements, &single); err != nil {
			return nil, fmt.Errorf("expected IAM Statement")
		}
		entries = []statement{single}
	}
	if len(entries) == 0 || len(entries) > 1000 {
		return nil, fmt.Errorf("policy must contain 1 to 1,000 statements")
	}
	r := newReport("iam", "Static AWS IAM policy review. No cloud credentials or provider requests.", data)
	for i, s := range entries {
		if s.Effect != "Allow" && s.Effect != "Deny" {
			return nil, fmt.Errorf("statement %d needs Effect Allow or Deny", i+1)
		}
		if s.Effect == "Deny" {
			continue
		}
		name := fmt.Sprintf("Statement %d", i+1)
		if s.SID != "" {
			name = s.SID
		}
		condition := "No condition is present."
		if len(s.Condition) > 0 {
			condition = "Conditions are present and may restrict access; their effectiveness needs manual review."
		}
		actions := []string{}
		if len(s.Action) > 0 {
			var err error
			actions, err = stringList(s.Action)
			if err != nil {
				return nil, fmt.Errorf("statement %d has invalid Action", i+1)
			}
		} else if len(s.NotAction) > 0 {
			r.finding("medium", "Allow with NotAction needs review", name, "This statement allows the complement of excluded actions. "+condition)
		} else {
			return nil, fmt.Errorf("statement %d needs Action or NotAction", i+1)
		}
		for _, action := range actions {
			r.observe("allowed action", name, action)
			if strings.ContainsAny(action, "*?") {
				r.finding("medium", "Wildcard allowed action", name, "Action "+action+". "+condition)
			}
			switch strings.ToLower(action) {
			case "iam:passrole", "iam:createaccesskey", "iam:attachuserpolicy", "iam:attachrolepolicy", "iam:putrolepolicy", "sts:assumerole":
				r.finding("medium", "Sensitive IAM action", name, "Action "+action+". Review which resources and principals can use it. "+condition)
			}
		}
		if len(s.Resource) > 0 {
			resources, err := stringList(s.Resource)
			if err != nil {
				return nil, fmt.Errorf("statement %d has invalid Resource", i+1)
			}
			for _, resource := range resources {
				r.node("cloud resource", resource)
				if resource == "*" {
					r.finding("low", "All resources allowed by statement", name, "Some AWS actions require Resource *. Check whether narrower resources are supported. "+condition)
				}
			}
		}
		public := false
		if len(s.Principal) > 0 {
			if string(s.Principal) == `"*"` {
				public = true
			} else {
				var principal map[string]json.RawMessage
				if err := json.Unmarshal(s.Principal, &principal); err != nil {
					return nil, fmt.Errorf("invalid Principal")
				}
				if raw, ok := principal["AWS"]; ok {
					values, err := stringList(raw)
					if err != nil {
						return nil, fmt.Errorf("invalid AWS principal")
					}
					for _, value := range values {
						if value == "*" {
							public = true
						}
					}
				}
			}
		}
		if public {
			severity := "high"
			if len(s.Condition) > 0 {
				severity = "medium"
			}
			r.finding(severity, "Public principal in Allow statement", name, condition)
		}
	}
	r.gap("This is a lint pass, not AWS authorization simulation. Explicit denies, SCPs, permission boundaries, resource policies, trust context and condition effectiveness can change effective access.")
	return r, nil
}
