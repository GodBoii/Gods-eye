// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
)

var cloudLogicalID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,254}$`)
var cloudAction = regexp.MustCompile(`^[A-Za-z0-9*?]+:[A-Za-z0-9*?]+$|^\*$`)

func auditCloudFox(ctx context.Context, req ToolRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Target != "" || req.RunEngine {
		return nil, fmt.Errorf("CloudFox assessment accepts offline JSON only; leave target and engine empty")
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	if err := checkInput(data); err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := decodeJSON(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid cloud JSON document")
	}
	r := newReport("cloudfox", "Static AWS CloudFormation configuration review; no provider requests or effective-access verification.", data)
	r.gap("Template evidence does not establish deployed state. Account controls, networking, IAM conditions, defaults and runtime changes need independent verification.")
	resources, ok := doc["Resources"].(map[string]any)
	if !ok {
		if _, present := doc["Resources"]; present {
			return nil, fmt.Errorf("CloudFormation Resources must be an object")
		}
		if _, present := doc["Statement"]; !present {
			return nil, fmt.Errorf("expected CloudFormation Resources or IAM Statement")
		}
		if err := cloudPolicy(ctx, r, doc, "Policy"); err != nil {
			return nil, err
		}
		return r, nil
	}
	if len(resources) == 0 || len(resources) > 1000 {
		return nil, fmt.Errorf("provide 1 to 1,000 CloudFormation resources")
	}
	names := make([]string, 0, len(resources))
	for name := range resources {
		if !cloudLogicalID.MatchString(name) {
			return nil, fmt.Errorf("invalid resource logical ID")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	ids := map[string]string{}
	for _, name := range names {
		ids[name] = r.node("cloud resource", name)
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resource, ok := resources[name].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("resource must be an object")
		}
		props, ok := resource["Properties"].(map[string]any)
		if !ok && resource["Properties"] != nil {
			cloudUnknown(r, name+".Properties")
		}
		base := "Resources." + name + ".Properties"
		kind, _ := resource["Type"].(string)
		switch kind {
		case "AWS::S3::Bucket":
			if v, exists := props["AccessControl"]; exists {
				if acl, ok := v.(string); !ok {
					cloudUnknown(r, base+".AccessControl")
				} else if acl == "PublicRead" || acl == "PublicReadWrite" || acl == "AuthenticatedRead" {
					r.finding("medium", "S3 permissive ACL declared", base+".AccessControl", "Template declares a broad ACL. Object ownership and account/bucket public access blocks may reject or override it.")
				}
			}
			if v, exists := props["PublicAccessBlockConfiguration"]; exists {
				if block, ok := v.(map[string]any); ok && !cloudIntrinsic(block) {
					for _, key := range []string{"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"} {
						cloudBool(r, block, key, false, "medium", "S3 public access guard disabled", base+".PublicAccessBlockConfiguration")
					}
				} else {
					cloudUnknown(r, base+".PublicAccessBlockConfiguration")
				}
			} else {
				r.observe("configuration omission", base+".PublicAccessBlockConfiguration", "No explicit bucket block configuration. Account controls and current service defaults are not evaluated.")
			}
			if v, exists := props["BucketEncryption"]; !exists {
				r.observe("configuration omission", base+".BucketEncryption", "No explicit encryption declaration. S3 encrypts new uploads by default; this is not evidence of unencrypted objects.")
			} else if encryption, ok := v.(map[string]any); !ok || cloudIntrinsic(encryption) {
				cloudUnknown(r, base+".BucketEncryption")
			}
		case "AWS::RDS::DBInstance", "AWS::RDS::DBCluster":
			cloudBool(r, props, "PubliclyAccessible", true, "medium", "RDS public accessibility enabled", base)
			cloudBool(r, props, "StorageEncrypted", false, "high", "RDS storage encryption disabled", base)
		case "AWS::EC2::SecurityGroup":
			if v, exists := props["SecurityGroupIngress"]; exists {
				if entries, ok := v.([]any); ok && len(entries) <= 1000 {
					for i, entry := range entries {
						if rule, ok := entry.(map[string]any); ok {
							cloudIngress(r, rule, fmt.Sprintf("%s.SecurityGroupIngress[%d]", base, i))
						} else {
							cloudUnknown(r, base+".SecurityGroupIngress")
						}
					}
				} else {
					cloudUnknown(r, base+".SecurityGroupIngress")
				}
			}
		case "AWS::EC2::SecurityGroupIngress":
			cloudIngress(r, props, base)
		case "AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group", "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::S3::BucketPolicy":
			if policy, exists := props["PolicyDocument"]; exists {
				if err := cloudPolicy(ctx, r, policy, base+".PolicyDocument"); err != nil {
					cloudUnknown(r, base+".PolicyDocument")
				}
			}
			if policy, exists := props["AssumeRolePolicyDocument"]; exists {
				if err := cloudPolicy(ctx, r, policy, base+".AssumeRolePolicyDocument"); err != nil {
					cloudUnknown(r, base+".AssumeRolePolicyDocument")
				}
			}
			if v, exists := props["Policies"]; exists {
				if policies, ok := v.([]any); ok && len(policies) <= 1000 {
					for i, v := range policies {
						policy, ok := v.(map[string]any)
						path := fmt.Sprintf("%s.Policies[%d].PolicyDocument", base, i)
						if !ok {
							cloudUnknown(r, path)
							continue
						}
						if err := cloudPolicy(ctx, r, policy["PolicyDocument"], path); err != nil {
							cloudUnknown(r, path)
						}
					}
				} else {
					cloudUnknown(r, base+".Policies")
				}
			}
		default:
			r.Limited = true
			r.gap("Resource types outside S3, RDS, EC2 security groups and selected IAM resources are inventoried but not audited.")
		}
		if _, conditional := resource["Condition"]; conditional {
			cloudUnknown(r, "Resources."+name+".Condition")
		}
		budget := 10000
		cloudRefs(ctx, r, resource, ids[name], ids, 0, &budget)
	}
	return r, ctx.Err()
}

func cloudUnknown(r *Report, path string) {
	r.Limited = true
	r.observe("unknown configuration", path, "Value is unresolved or unsupported; no secure/insecure conclusion was made.")
	r.gap("Intrinsic functions and conditional values are not resolved. Review unknown properties in the deployed configuration.")
}

func cloudIntrinsic(value map[string]any) bool {
	for key := range value {
		if key == "Ref" || len(key) > 4 && key[:4] == "Fn::" {
			return true
		}
	}
	return false
}

func cloudBool(r *Report, props map[string]any, key string, risky bool, severity, title, base string) {
	v, exists := props[key]
	if !exists {
		r.observe("configuration omission", base+"."+key, "Property is absent; defaults and deployment context were not evaluated.")
		return
	}
	b, ok := v.(bool)
	if !ok {
		cloudUnknown(r, base+"."+key)
		return
	}
	if b == risky {
		r.finding(severity, title, base+"."+key, "Explicit template boolean requests this configuration. Review deployed state and compensating controls.")
	}
}

func cloudIngress(r *Report, rule map[string]any, path string) {
	world := false
	for _, key := range []string{"CidrIp", "CidrIpv6"} {
		if v, exists := rule[key]; exists {
			s, ok := v.(string)
			if !ok {
				cloudUnknown(r, path+"."+key)
			} else if s == "0.0.0.0/0" || s == "::/0" {
				world = true
			}
		}
	}
	if !world {
		return
	}
	protocol, ok := rule["IpProtocol"].(string)
	if !ok {
		cloudUnknown(r, path+".IpProtocol")
		return
	}
	if protocol == "-1" {
		r.finding("high", "World-open unrestricted ingress", path, "All IP protocols are allowed from a world CIDR. Routes, NACLs and attached resources are not evaluated.")
		return
	}
	if protocol != "tcp" && protocol != "udp" && protocol != "6" && protocol != "17" {
		return
	}
	from, okFrom := rule["FromPort"].(float64)
	to, okTo := rule["ToPort"].(float64)
	if !okFrom || !okTo || from < 0 || to > 65535 || from > to || from != float64(int(from)) || to != float64(int(to)) {
		cloudUnknown(r, path+".FromPort/ToPort")
		return
	}
	for _, port := range []int{22, 23, 135, 139, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 11211, 27017} {
		if float64(port) >= from && float64(port) <= to {
			r.finding("high", "World-open administrative or database port", path, fmt.Sprintf("World CIDR permits %s port %d. This is a configuration finding; reachability and service authentication are unverified.", protocol, port))
		}
	}
}

// Pass only allowlisted IAM fields to the existing analyzer. Never retain Sids,
// ARN strings, principal names, condition values or unrelated template secrets.
func cloudPolicy(ctx context.Context, r *Report, value any, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	doc, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("expected IAM policy object")
	}
	statements, ok := doc["Statement"].([]any)
	if !ok {
		if single, ok := doc["Statement"].(map[string]any); ok {
			statements = []any{single}
		} else {
			return fmt.Errorf("expected IAM statements")
		}
	}
	if len(statements) == 0 || len(statements) > 1000 {
		return fmt.Errorf("provide 1 to 1,000 IAM statements")
	}
	for i, v := range statements {
		if err := ctx.Err(); err != nil {
			return err
		}
		s, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid IAM statement")
		}
		effect, ok := s["Effect"].(string)
		if !ok || (effect != "Allow" && effect != "Deny") {
			return fmt.Errorf("invalid IAM effect")
		}
		clean := map[string]any{"Effect": effect}
		statementPath := fmt.Sprintf("%s.Statement[%d]", path, i)
		for _, key := range []string{"Action", "NotAction", "Resource"} {
			v, exists := s[key]
			if !exists {
				continue
			}
			items, ok := v.([]any)
			if !ok {
				items = []any{v}
			}
			if len(items) > 1000 {
				return fmt.Errorf("IAM list exceeds 1,000 entries")
			}
			values := []string{}
			for _, item := range items {
				str, ok := item.(string)
				if !ok {
					cloudUnknown(r, statementPath+"."+key)
					continue
				}
				if key == "Resource" {
					if str != "*" {
						str = "redacted-resource"
					}
				} else if !cloudAction.MatchString(str) {
					cloudUnknown(r, statementPath+"."+key)
					continue
				}
				values = append(values, str)
			}
			if len(values) > 0 {
				clean[key] = values
			}
		}
		if _, present := clean["Action"]; !present {
			if _, present := clean["NotAction"]; !present {
				cloudUnknown(r, statementPath+".Action")
				continue
			}
		}
		if principal, exists := s["Principal"]; exists {
			if str, ok := principal.(string); ok && str == "*" {
				clean["Principal"] = "*"
			} else if p, ok := principal.(map[string]any); ok {
				if cloudIntrinsic(p) {
					cloudUnknown(r, statementPath+".Principal")
				}
				vals, _ := p["AWS"].([]any)
				vals = append(vals, p["AWS"])
				for _, val := range vals {
					if _, ok := val.(map[string]any); ok {
						cloudUnknown(r, statementPath+".Principal.AWS")
					}
					if val == "*" {
						clean["Principal"] = "*"
					}
				}
			} else {
				cloudUnknown(r, statementPath+".Principal")
			}
		}
		if _, exists := s["Condition"]; exists {
			clean["Condition"] = map[string]any{"Unresolved": true}
			cloudUnknown(r, statementPath+".Condition")
		}
		encoded, err := json.Marshal(map[string]any{"Statement": clean})
		if err != nil {
			return err
		}
		policy, err := IAM(encoded)
		if err != nil {
			return fmt.Errorf("unsupported IAM policy structure")
		}
		for _, f := range policy.Findings {
			r.finding(f.Severity, f.Title, statementPath, f.Detail)
		}
		for _, gap := range policy.Gaps {
			r.gap(gap)
		}
	}
	return nil
}

func cloudRefs(ctx context.Context, r *Report, value any, source string, ids map[string]string, depth int, budget *int) {
	*budget--
	if depth > 32 || *budget < 0 {
		r.Limited = true
		r.gap("Resource reference traversal reached its depth or item limit.")
		return
	}
	if ctx.Err() != nil {
		return
	}
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if key == "Ref" || key == "DependsOn" {
				if name, ok := item.(string); ok {
					r.edge(source, ids[name], key)
				}
				if names, ok := item.([]any); ok {
					for _, name := range names {
						if str, ok := name.(string); ok {
							r.edge(source, ids[str], key)
						}
					}
				}
			}
			if key == "Fn::GetAtt" {
				if name, ok := item.(string); ok {
					for i, ch := range name {
						if ch == '.' {
							r.edge(source, ids[name[:i]], "GetAtt")
							break
						}
					}
				}
				if names, ok := item.([]any); ok && len(names) > 0 {
					if name, ok := names[0].(string); ok {
						r.edge(source, ids[name], "GetAtt")
					}
				}
			}
			cloudRefs(ctx, r, item, source, ids, depth+1, budget)
			if *budget < 0 {
				return
			}
		}
	case []any:
		for _, item := range v {
			cloudRefs(ctx, r, item, source, ids, depth+1, budget)
			if *budget < 0 {
				return
			}
		}
	}
}
