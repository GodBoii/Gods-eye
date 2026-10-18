// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func cloudRun(t *testing.T, input string) *Report {
	t.Helper()
	r, err := auditCloudFox(context.Background(), ToolRequest{Input: input})
	if err != nil {
		t.Fatal(err)
	}
	if r.Tool != "cloudfox" || r.InputSHA256 != digest([]byte(input)) {
		t.Fatal("missing report identity")
	}
	return r
}

func cloudFinding(r *Report, title string) bool {
	for _, f := range r.Findings {
		if f.Title == title {
			return true
		}
	}
	return false
}

func TestCloudFoxInsecureTemplate(t *testing.T) {
	r := cloudRun(t, `{"Resources":{
	"Bucket":{"Type":"AWS::S3::Bucket","Properties":{"AccessControl":"PublicRead","PublicAccessBlockConfiguration":{"BlockPublicAcls":false}}},
	"Database":{"Type":"AWS::RDS::DBInstance","Properties":{"PubliclyAccessible":true,"StorageEncrypted":false,"VPCSecurityGroups":[{"Ref":"Firewall"}],"MasterUserPassword":"secret-password-do-not-retain"}},
	"Firewall":{"Type":"AWS::EC2::SecurityGroup","Properties":{"SecurityGroupIngress":[{"CidrIpv6":"::/0","IpProtocol":"tcp","FromPort":5432,"ToPort":5432}]}},
	"Role":{"Type":"AWS::IAM::Role","Properties":{"Policies":[{"PolicyDocument":{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}}]}}
	}}`)
	for _, title := range []string{"S3 permissive ACL declared", "S3 public access guard disabled", "RDS public accessibility enabled", "RDS storage encryption disabled", "World-open administrative or database port", "Wildcard allowed action"} {
		if !cloudFinding(r, title) {
			t.Errorf("missing %s", title)
		}
	}
	if len(r.Edges) != 1 || r.Edges[0].Relation != "Ref" {
		t.Fatalf("missing resource relationship: %+v", r.Edges)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret-password") {
		t.Fatal("secret retained")
	}
	for _, f := range r.Findings {
		if !strings.HasPrefix(f.Target, "Resources.") {
			t.Fatalf("missing property provenance: %+v", f)
		}
	}
}

func TestCloudFoxSecureAndDefaultEncryption(t *testing.T) {
	r := cloudRun(t, `{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket","Properties":{"AccessControl":"Private","PublicAccessBlockConfiguration":{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":true}}},"Database":{"Type":"AWS::RDS::DBInstance","Properties":{"PubliclyAccessible":false,"StorageEncrypted":true}},"Firewall":{"Type":"AWS::EC2::SecurityGroupIngress","Properties":{"CidrIp":"10.0.0.0/8","IpProtocol":"tcp","FromPort":22,"ToPort":22}}}}`)
	if len(r.Findings) != 0 {
		t.Fatalf("false positives: %+v", r.Findings)
	}
	found := false
	for _, o := range r.Observations {
		if strings.HasSuffix(o.Target, ".BucketEncryption") && strings.Contains(o.Value, "default") {
			found = true
		}
	}
	if !found {
		t.Fatal("missing encryption default caveat")
	}
}

func TestCloudFoxUnresolvedValues(t *testing.T) {
	r := cloudRun(t, `{"Resources":{"Database":{"Type":"AWS::RDS::DBInstance","Properties":{"PubliclyAccessible":{"Ref":"Public"},"StorageEncrypted":{"Fn::If":["Encrypt",true,false]}}},"Bucket":{"Type":"AWS::S3::Bucket","Properties":{"PublicAccessBlockConfiguration":{"Fn::If":["Block",{},{}]},"BucketEncryption":{"Ref":"Encryption"}}},"Firewall":{"Type":"AWS::EC2::SecurityGroupIngress","Properties":{"CidrIp":"0.0.0.0/0","IpProtocol":"tcp","FromPort":{"Ref":"Port"},"ToPort":22}}}}`)
	if !r.Limited || len(r.Findings) != 0 {
		t.Fatalf("unknown treated as verified: %+v", r)
	}
	unknowns := 0
	for _, o := range r.Observations {
		if o.Kind == "unknown configuration" {
			unknowns++
		}
	}
	if unknowns < 5 {
		t.Fatalf("expected unknown property evidence, got %d", unknowns)
	}
}

func TestCloudFoxIAMFallbackAndRedaction(t *testing.T) {
	input := `{"Statement":[{"Sid":"secret-sid","Effect":"Allow","Action":["s3:*","iam:PassRole"],"Resource":["*","arn:secret-resource"],"Principal":{"AWS":["*","secret-principal"]},"Condition":{"StringEquals":{"secret-condition":"secret-value"}}}]}`
	r := cloudRun(t, input)
	if !cloudFinding(r, "Wildcard allowed action") || !cloudFinding(r, "Public principal in Allow statement") || !r.Limited {
		t.Fatalf("IAM fallback incomplete: %+v", r)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret-") {
		t.Fatalf("secret IAM values retained: %s", b)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(input))
	if _, err := auditCloudFox(context.Background(), ToolRequest{Input: encoded, Encoding: "base64"}); err != nil {
		t.Fatal(err)
	}
}

func TestCloudFoxBoundaries(t *testing.T) {
	for _, req := range []ToolRequest{{Input: `{}`}, {Input: `{"Resources":{}}`}, {Input: `{"Statement":[]}`}, {Input: `{"Resources":{"bad/id":{}}}`}, {Input: `{} {}`}, {Input: "%%%", Encoding: "base64"}, {Input: strings.Repeat("x", MaxInput+1)}, {Input: `{}`, Target: "example.test"}, {Input: `{}`, RunEngine: true}} {
		if _, err := auditCloudFox(context.Background(), req); err == nil {
			t.Errorf("accepted invalid request, length=%d", len(req.Input))
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := auditCloudFox(ctx, ToolRequest{Input: `{}`}); err == nil {
		t.Fatal("ignored cancellation")
	}
	resources := map[string]any{}
	for i := 0; i < 1001; i++ {
		resources[fmt.Sprintf("Resource%d", i)] = map[string]any{"Type": "AWS::S3::Bucket"}
	}
	data, err := json.Marshal(map[string]any{"Resources": resources})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditCloudFox(context.Background(), ToolRequest{Input: string(data)}); err == nil {
		t.Fatal("accepted oversized resource inventory")
	}
}

func TestCloudFoxAllProtocolAndNonAdminIngress(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		from, to int
		want     bool
	}{{"-1", 0, 0, true}, {"tcp", 80, 80, false}, {"tcp", 0, 65535, true}, {"icmp", 0, 65535, false}} {
		input := fmt.Sprintf(`{"Resources":{"Rule":{"Type":"AWS::EC2::SecurityGroupIngress","Properties":{"CidrIp":"0.0.0.0/0","IpProtocol":%q,"FromPort":%d,"ToPort":%d}}}}`, tc.protocol, tc.from, tc.to)
		r := cloudRun(t, input)
		if (len(r.Findings) > 0) != tc.want {
			t.Errorf("protocol %s findings=%v", tc.protocol, r.Findings)
		}
	}
}
