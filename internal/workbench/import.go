// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type Format struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Extension string `json:"extension"`
}

func Formats() []Format {
	return []Format{
		{"nmap", "Nmap XML", ".xml"}, {"nuclei", "Nuclei JSON / JSONL", ".json,.jsonl"},
		{"har", "HTTP archive, HAR 1.2", ".har,.json"}, {"burp", "Burp issue XML", ".xml"},
		{"shodan", "Shodan host JSON / JSONL", ".json,.jsonl"}, {"bbot", "BBOT event JSON / JSONL", ".json,.jsonl"},
		{"bloodhound", "BloodHound v5/v6 collection JSON", ".json"}, {"aircrack", "Airodump-ng access-point CSV", ".csv"},
		{"cloudfox", "CloudFox resource / endpoint CSV", ".csv"}, {"spiderfoot", "SpiderFoot event CSV", ".csv"},
		{"recon-ng", "recon-ng host CSV", ".csv"}, {"sqlmap", "sqlmap results CSV", ".csv"},
		{"metasploit", "Metasploit database XML", ".xml"}, {"tshark", "TShark packet JSON", ".json"},
	}
}

func Import(format string, data []byte) (*Report, error) {
	if err := checkInput(data); err != nil {
		return nil, err
	}
	r := newReport(format, "Imported evidence. Observations have not been independently verified.", data)
	r.gap("Only supported fields are imported. Raw HTTP bodies, cookies, authorization headers and extracted secrets are omitted. Names, titles and paths may still be sensitive.")
	var err error
	switch format {
	case "nmap":
		err = importNmap(r, data)
	case "nuclei":
		err = importNuclei(r, data)
	case "har":
		err = importHAR(r, data)
	case "burp":
		err = importBurp(r, data)
	case "shodan":
		err = importShodan(r, data)
	case "bbot":
		err = importBBOT(r, data)
	case "bloodhound":
		err = importBloodHound(r, data)
	case "aircrack", "cloudfox", "spiderfoot", "recon-ng", "sqlmap":
		err = importCSV(r, format, data)
	case "metasploit":
		err = importMetasploit(r, data)
	case "tshark":
		err = importTShark(r, data)
	default:
		return nil, fmt.Errorf("unsupported report format")
	}
	if err != nil {
		return nil, fmt.Errorf("invalid %s report: %w", format, err)
	}
	return r, nil
}

func decodeJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("malformed JSON or incompatible field types")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("expected one JSON document")
	}
	return nil
}

// Stream arrays and JSONL without allocating an unbounded slice. Every retained
// record is validated. Large exports must be split before import.
func jsonRecords[T any](data []byte, consume func(T) error) error {
	data = bytes.TrimSpace(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	if len(data) > 0 && data[0] == '[' {
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("invalid JSON array")
		}
		for count := 0; decoder.More(); count++ {
			if count >= 10000 {
				return fmt.Errorf("split exports containing more than 10,000 input records")
			}
			var record T
			if err := decoder.Decode(&record); err != nil {
				return fmt.Errorf("malformed JSON record %d", count+1)
			}
			if err := consume(record); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("invalid JSON array ending")
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return fmt.Errorf("expected one JSON array")
		}
		return nil
	}
	for count := 0; ; count++ {
		var record T
		err := decoder.Decode(&record)
		if err == io.EOF {
			if count == 0 {
				return fmt.Errorf("no JSON records")
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("malformed JSON record %d", count+1)
		}
		if count >= 10000 {
			return fmt.Errorf("split exports containing more than 10,000 input records")
		}
		if err := consume(record); err != nil {
			return err
		}
	}
}
