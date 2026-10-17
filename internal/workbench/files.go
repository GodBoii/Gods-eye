// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net/http"
	"sort"
)

func InspectFile(data []byte) (*Report, error) {
	if err := checkInput(data); err != nil {
		return nil, err
	}
	r := newReport("file", "Offline file identification and bounded signature recovery.", data)
	r.observe("size", "input", fmt.Sprintf("%d bytes", len(data)))
	r.observe("media type", "input", http.DetectContentType(data))
	r.observe("SHA-256", "input", digest(data))
	counts := [256]int{}
	for _, b := range data {
		counts[b]++
	}
	entropy := 0.0
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / float64(len(data))
			entropy -= p * math.Log2(p)
		}
	}
	r.observe("byte entropy", "input", fmt.Sprintf("%.4f bits/byte; compression and encryption can both produce high entropy", entropy))
	type signature struct {
		name       string
		start, end []byte
	}
	signatures := []signature{
		{"jpeg", []byte{0xff, 0xd8, 0xff}, []byte{0xff, 0xd9}},
		{"png", []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, []byte{0, 0, 0, 0, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82}},
		{"pdf", []byte("%PDF-"), []byte("%%EOF")},
	}
	for _, sig := range signatures {
		for offset := 0; offset < len(data); {
			i := bytes.Index(data[offset:], sig.start)
			if i < 0 {
				break
			}
			i += offset
			end := bytes.Index(data[i+len(sig.start):], sig.end)
			if end < 0 {
				r.gap("At least one file signature had no end marker; it was not offered for recovery.")
				break
			}
			length := len(sig.start) + end + len(sig.end)
			r.Artifacts = append(r.Artifacts, Artifact{fmt.Sprintf("recovered-%d.%s", i, sig.name), i, length})
			if len(r.Artifacts) >= 32 {
				r.Limited = true
				r.gap("Recovery stopped at 32 signature candidates.")
				break
			}
			offset = i + length
		}
		if len(r.Artifacts) >= 32 {
			break
		}
	}
	// ZIP length is obtained from its end-of-central-directory structure. ZIP64
	// and split archives deliberately stay outside this small signature carver.
	for offset := 0; offset < len(data) && len(r.Artifacts) < 32; {
		start := bytes.Index(data[offset:], []byte{'P', 'K', 3, 4})
		if start < 0 {
			break
		}
		start += offset
		end := bytes.Index(data[start:], []byte{'P', 'K', 5, 6})
		if end < 0 {
			break
		}
		end += start
		if end+22 > len(data) {
			r.gap("A truncated ZIP end record was omitted.")
			break
		}
		comment := int(binary.LittleEndian.Uint16(data[end+20 : end+22]))
		finish := end + 22 + comment
		if finish > len(data) {
			r.gap("A truncated ZIP comment was omitted.")
			break
		}
		r.Artifacts = append(r.Artifacts, Artifact{fmt.Sprintf("recovered-%d.zip", start), start, finish - start})
		offset = finish
	}
	sort.Slice(r.Artifacts, func(i, j int) bool { return r.Artifacts[i].Offset < r.Artifacts[j].Offset })
	for _, artifact := range r.Artifacts {
		r.observe("recovery candidate", artifact.Name, fmt.Sprintf("offset %d · %d bytes", artifact.Offset, artifact.Length))
	}
	r.gap("PNG, JPEG, PDF and ordinary ZIP signature candidates only. End markers can occur in content; recovered slices may be false positives or incomplete. No filesystem reconstruction, archive extraction, malware verdict or automatic file execution.")
	return r, nil
}
