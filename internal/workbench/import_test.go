// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestImportFormats(t *testing.T) {
	for _, tc := range []struct {
		format, data           string
		findings, observations int
	}{
		{"nmap", `<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Fixture"/></port><port protocol="tcp" portid="80"><state state="closed"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`, 0, 1},
		{"nuclei", `{"template-id":"fixture","info":{"name":"Fixture finding","severity":"high"},"matched-at":"https://user:password@example.test/a?token=SECRET","request":"SECRET","response":"SECRET"}`, 1, 0},
		{"har", `{"log":{"version":"1.2","entries":[{"request":{"method":"GET","url":"https://example.test/a?token=SECRET","headers":[{"name":"Authorization","value":"SECRET"}]},"response":{"status":200,"headers":[],"content":{"text":"SECRET"}},"time":3}]}}`, 1, 1},
		{"burp", `<issues><issue><name>Fixture</name><host>https://example.test</host><path>/</path><severity>High</severity><confidence>Firm</confidence><requestresponse><request>SECRET</request></requestresponse></issue></issues>`, 1, 0},
		{"shodan", `{"ip_str":"192.0.2.1","data":[{"port":443,"transport":"tcp","product":"Fixture","vulns":{"CVE-2025-0000":{}},"data":"SECRET"}]}`, 1, 1},
		{"bbot", `{"type":"DNS_NAME","data":"example.test","module":"fixture","scope_distance":0}`, 0, 1},
		{"bloodhound", `{"meta":{"type":"groups","version":6},"data":[{"ObjectIdentifier":"S-1-FIXTURE","Properties":{"name":"Fixture group"},"Aces":[{"PrincipalSID":"S-1-OTHER","RightName":"GenericAll"}],"Members":[{"ObjectIdentifier":"S-1-MEMBER"}]}]}`, 1, 1},
		{"aircrack", "BSSID,First time seen,Last time seen,channel,Speed,Privacy,Cipher,Authentication,Power,# beacons,# IV,LAN IP,ID-length,ESSID,Key\n00:11:22:33:44:55,now,now,1,54,WEP,WEP,,0,1,0,0,7,Fixture,\n\nStation MAC,First time seen\nAA:BB:CC:DD:EE:FF,SECRET\n", 1, 1},
		{"cloudfox", "Account,Service,Region,ARN,Public\n123,s3,us-east-1,arn:aws:s3:::fixture,true\n", 1, 1},
		{"spiderfoot", "Updated,Type,Module,Source,Data\nnow,INTERNET_NAME,fixture,seed,example.test\n", 0, 1},
		{"recon-ng", "host,ip_address,region,country,latitude,longitude,notes,module\nexample.test,192.0.2.1,,,,,,fixture\n", 0, 1},
		{"sqlmap", "Target URL,Place,Parameter,Technique(s),Notes\nhttps://example.test/a?token=SECRET,GET,id,B,SECRET\n", 1, 0},
		{"metasploit", `<MetasploitV5><hosts><host><address>192.0.2.1</address><services><service><port>443</port><proto>tcp</proto><name>https</name><state>open</state></service></services><vulns><vuln><name>Fixture</name></vuln></vulns><creds>SECRET</creds></host></hosts></MetasploitV5>`, 1, 1},
		{"tshark", `[{"_source":{"layers":{"ip":{"ip.src":"192.0.2.1","ip.dst":"192.0.2.2"},"frame":{"frame.protocols":"eth:ip:tcp"},"http":{"authorization":"SECRET"}}}}]`, 0, 1},
	} {
		t.Run(tc.format, func(t *testing.T) {
			r, err := Import(tc.format, []byte(tc.data))
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Findings) != tc.findings || len(r.Observations) != tc.observations {
				t.Fatalf("unexpected report: %+v", r)
			}
			encoded, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"SECRET", "password@", "?token="} {
				if strings.Contains(string(encoded), forbidden) {
					t.Fatalf("raw sensitive field retained: %s", forbidden)
				}
			}
			if r.InputSHA256 == "" {
				t.Fatal("missing input provenance")
			}
		})
	}
}

func TestMalformedReportsAndBounds(t *testing.T) {
	for _, tc := range []struct{ format, data string }{
		{"nmap", `<issues/>`}, {"nmap", `<nmaprun/><extra/>`}, {"nuclei", `{}`}, {"nuclei", `{"template-id":"x","info":{"name":"x"}} garbage`},
		{"har", `{}`}, {"shodan", `{"ip_str":"example.test","port":443}`}, {"bbot", `{"type":"DNS_NAME","data":{}}`},
		{"bloodhound", `{"meta":{"type":"groups","version":4},"data":[]}`}, {"aircrack", "host,ip\na,b\n"},
		{"cloudfox", "ARN,Public\nfoo,true,extra\n"}, {"spiderfoot", "No,Data\na,b\n"}, {"recon-ng", "name\na\n"},
		{"sqlmap", "Target URL,Parameter\nhttps://example.test,id\n"}, {"metasploit", `<MetasploitV5><hosts><host><address>invalid</address></host></hosts></MetasploitV5>`}, {"tshark", `[{}]`},
	} {
		if _, err := Import(tc.format, []byte(tc.data)); err == nil {
			t.Errorf("accepted malformed %s: %s", tc.format, tc.data)
		}
	}
	if _, err := Import("nmap", make([]byte, MaxInput+1)); err == nil {
		t.Fatal("oversized report accepted")
	}
	if _, err := Import("unknown", []byte(`{}`)); err == nil {
		t.Fatal("unknown format accepted")
	}
	data := strings.Repeat(`{"template-id":"fixture","info":{"name":"A","severity":"low"},"host":"example.test"}`+"\n", 1005)
	r, err := Import("nuclei", []byte(data))
	if err != nil || len(r.Findings) != 1 {
		t.Fatal("duplicate findings not deduplicated", err)
	}
	data = strings.Repeat(`{"type":"DNS_NAME","data":"example.test"}`+"\n", 1005)
	r, err = Import("bbot", []byte(data))
	if err != nil || !r.Limited || len(r.Observations) != maxRecords {
		t.Fatal("record limit not reported", err)
	}
}

func TestOutOfScopeAndFalseMatches(t *testing.T) {
	rClean, cleanErr := Import("sqlmap", []byte("Target URL,Place,Parameter,Technique(s),Note(s)\nhttps://example.test,,,,\n"))
	if cleanErr != nil || len(rClean.Findings) != 0 || len(rClean.Observations) != 1 {
		t.Fatal("clean sqlmap row became a vulnerability", rClean, cleanErr)
	}
	tooMany := "[" + strings.Repeat(`{"type":"DNS_NAME","data":"example.test"},`, 10000) + `{"type":"DNS_NAME","data":"example.test"}]`
	if _, err := Import("bbot", []byte(tooMany)); err == nil {
		t.Fatal("input-record limit was not enforced")
	}
	r, err := Import("bbot", []byte(`{"type":"DNS_NAME","data":"outside.test","scope_distance":1}`))
	if err != nil || len(r.Nodes) != 0 || len(r.Gaps) < 2 {
		t.Fatal(r, err)
	}
	r, err = Import("nuclei", []byte(`{"template-id":"fixture","info":{"name":"Fixture","severity":"critical"},"matcher-status":false}`))
	if err != nil || len(r.Findings) != 0 {
		t.Fatal(r, err)
	}
}
