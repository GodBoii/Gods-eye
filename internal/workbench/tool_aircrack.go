// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
)

func auditAircrack(ctx context.Context, req ToolRequest) (*Report, error) {
	if req.RunEngine {
		return nil, fmt.Errorf("wireless engine execution is not supported")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := toolInput(req)
	if err != nil {
		return nil, err
	}
	if err := checkInput(data); err != nil {
		return nil, err
	}
	if len(data) >= 4 {
		magic := binary.BigEndian.Uint32(data[:4])
		if magic == 0xa1b2c3d4 || magic == 0xa1b23c4d || magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1 || magic == 0x0a0d0d0a {
			return auditWirelessPCAP(ctx, data)
		}
	}
	report, err := Import("aircrack", data)
	if err == nil {
		err = ctx.Err()
	}
	return report, err
}

type wirelessAP struct {
	ssid, protection string
	beacons          int
}

func auditWirelessPCAP(ctx context.Context, data []byte) (*Report, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("truncated wireless PCAP header")
	}
	var order binary.ByteOrder
	switch binary.BigEndian.Uint32(data[:4]) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		order = binary.BigEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		order = binary.LittleEndian
	default:
		return nil, fmt.Errorf("export classic IEEE 802.11 or radiotap PCAP; PCAPNG is not supported")
	}
	if order.Uint16(data[4:6]) != 2 || order.Uint16(data[6:8]) != 4 {
		return nil, fmt.Errorf("unsupported PCAP version")
	}
	link := order.Uint32(data[20:24]) & 0xffff
	if link != 105 && link != 127 {
		return nil, fmt.Errorf("wireless analysis requires IEEE 802.11 link type 105 or radiotap link type 127")
	}
	snap := order.Uint32(data[16:20])
	if snap == 0 {
		return nil, fmt.Errorf("invalid PCAP snapshot length")
	}
	r := newReport("aircrack", "Offline wireless beacon protection and management-event analysis.", data)
	aps := make(map[string]wirelessAP)
	packets, skipped, deauth, disassoc := 0, 0, 0, 0
	for offset := 24; offset < len(data); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if packets >= 100000 {
			r.Limited = true
			r.gap("Wireless analysis stopped at 100,000 packets.")
			break
		}
		if len(data)-offset < 16 {
			return nil, fmt.Errorf("truncated wireless PCAP record header")
		}
		captured, original := order.Uint32(data[offset+8:offset+12]), order.Uint32(data[offset+12:offset+16])
		offset += 16
		if captured > original || captured > snap || uint64(captured) > uint64(len(data)-offset) {
			return nil, fmt.Errorf("invalid wireless PCAP record length")
		}
		frame := data[offset : offset+int(captured)]
		offset += int(captured)
		packets++
		if captured < original {
			r.Limited = true
			r.gap("Truncated capture records were omitted from wireless analysis.")
			skipped++
			continue
		}
		if link == 127 {
			var ok bool
			frame, ok = wirelessRadiotap(frame)
			if !ok {
				skipped++
				r.Limited = true
				r.gap("Malformed radiotap or bad-FCS frames were omitted.")
				continue
			}
		}
		if len(frame) < 2 {
			skipped++
			r.Limited = true
			continue
		}
		fc := binary.LittleEndian.Uint16(frame[:2])
		if fc&0xf != 0 {
			continue
		} // Management frames, protocol version zero.
		if len(frame) < 24 || fc&0x0300 != 0 {
			skipped++
			r.Limited = true
			continue
		}
		switch (fc >> 4) & 15 {
		case 12, 10:
			if len(frame) < 26 || fc&0x4000 != 0 {
				skipped++
				r.Limited = true
				continue
			}
			if (fc>>4)&15 == 12 {
				deauth++
			} else {
				disassoc++
			}
		case 8:
			if fc&0x4000 != 0 || len(frame) < 36 {
				skipped++
				r.Limited = true
				continue
			}
			bssid := frame[16:22]
			if bssid[0]&1 != 0 || bytes.Equal(bssid, make([]byte, 6)) || !bytes.Equal(frame[10:16], bssid) {
				skipped++
				r.Limited = true
				continue
			}
			ssid, protection, err := wirelessBeacon(frame)
			if err != nil {
				skipped++
				r.Limited = true
				r.gap("Malformed beacon information elements were omitted; protection could not be classified.")
				continue
			}
			target := net.HardwareAddr(bssid).String()
			// Retain separate observations if an AP changes advertised protection.
			key := target + "/" + protection + "/" + ssid
			if old, ok := aps[key]; ok {
				old.beacons++
				aps[key] = old
				continue
			}
			if len(aps) >= maxRecords {
				r.limit()
				continue
			}
			aps[key] = wirelessAP{ssid: ssid, protection: protection, beacons: 1}
		}
	}
	keys := make([]string, 0, len(aps))
	for key := range aps {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		ap := aps[key]
		target := key[:17]
		r.observe("wireless access point", target, fmt.Sprintf("SSID %q · %s · %d beacons", ap.ssid, ap.protection, ap.beacons))
		r.node("access point", target)
		switch ap.protection {
		case "Open":
			r.finding("high", "Open wireless access point", target, "The beacon has no privacy capability and no WPA or RSN element. Confirm this is intentional; beacon data does not prove network access.")
		case "Legacy privacy, possible WEP":
			r.finding("medium", "Legacy wireless protection advertised", target, "Privacy is enabled without a WPA or RSN element. This is consistent with WEP, but the capture alone does not verify the encryption in use.")
		case "WPA":
			r.finding("medium", "Legacy WPA advertised", target, "The beacon advertises the legacy WPA vendor element without RSN. Review support for current WPA2/WPA3 settings.")
		}
	}
	r.observe("wireless capture", "capture", fmt.Sprintf("%d records · %d omitted malformed/truncated frames · %d deauthentication · %d disassociation frames", packets, skipped, deauth, disassoc))
	if skipped > 0 {
		r.gap("Some frames were omitted; absence of an observation does not establish absence in the original capture.")
	}
	if deauth+disassoc > 0 {
		r.gap("Deauthentication/disassociation counts include retransmissions and normal disconnects. They do not establish an attack; protected management frames are not decoded.")
	}
	r.gap("Offline beacon evidence only. SSIDs and AP BSSIDs are retained; client identities, packet payloads, handshakes and keys are omitted. No radio capture, injection or password cracking. No proof of reachability, exploitable weakness, WPA3 enforcement or complete wireless coverage.")
	return r, nil
}

// Read only the radiotap header and flags needed to strip an appended FCS.
func wirelessRadiotap(packet []byte) ([]byte, bool) {
	if len(packet) < 8 || packet[0] != 0 {
		return nil, false
	}
	size := int(binary.LittleEndian.Uint16(packet[2:4]))
	if size < 8 || size > len(packet) {
		return nil, false
	}
	present := binary.LittleEndian.Uint32(packet[4:8])
	fields := 8
	word := present
	for word&0x80000000 != 0 {
		if fields+4 > size {
			return nil, false
		}
		word = binary.LittleEndian.Uint32(packet[fields : fields+4])
		fields += 4
	}
	if present&1 != 0 {
		fields = (fields + 7) &^ 7
		fields += 8
	}
	flags := byte(0)
	if present&2 != 0 {
		if fields >= size {
			return nil, false
		}
		flags = packet[fields]
	}
	if flags&0x40 != 0 {
		return nil, false
	}
	frame := packet[size:]
	if flags&0x10 != 0 {
		if len(frame) < 4 {
			return nil, false
		}
		frame = frame[:len(frame)-4]
	}
	return frame, true
}

func wirelessBeacon(frame []byte) (string, string, error) {
	ssid, foundSSID, rsn, wpa := "", false, false, false
	for offset := 36; offset < len(frame); {
		if len(frame)-offset < 2 {
			return "", "", fmt.Errorf("truncated information element")
		}
		id, size := frame[offset], int(frame[offset+1])
		offset += 2
		if size > len(frame)-offset {
			return "", "", fmt.Errorf("invalid information element length")
		}
		element := frame[offset : offset+size]
		offset += size
		switch id {
		case 0:
			if foundSSID || size > 32 {
				return "", "", fmt.Errorf("invalid SSID element")
			}
			foundSSID = true
			ssid = text(string(element))
		case 48:
			if rsn || !wirelessSecurityElement(element, true) {
				return "", "", fmt.Errorf("invalid RSN element")
			}
			rsn = true
		case 221:
			if len(element) >= 4 && bytes.Equal(element[:4], []byte{0, 0x50, 0xf2, 1}) {
				if wpa || !wirelessSecurityElement(element[4:], false) {
					return "", "", fmt.Errorf("invalid WPA element")
				}
				wpa = true
			}
		}
	}
	if !foundSSID {
		return "", "", fmt.Errorf("missing SSID element")
	}
	if ssid == "" {
		ssid = "<hidden>"
	}
	protection := "Open"
	if binary.LittleEndian.Uint16(frame[34:36])&0x10 != 0 {
		protection = "Legacy privacy, possible WEP"
	}
	if wpa {
		protection = "WPA"
	}
	if rsn {
		protection = "RSN advertised (WPA2/WPA3 family)"
	}
	return ssid, protection, nil
}

func wirelessSecurityElement(data []byte, rsn bool) bool {
	if len(data) < 8 || binary.LittleEndian.Uint16(data[:2]) != 1 {
		return false
	}
	offset := 6 // Version and group cipher.
	for i := 0; i < 2; i++ {
		if len(data)-offset < 2 {
			return false
		}
		count := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if count == 0 || count > (len(data)-offset)/4 {
			return false
		}
		offset += count * 4
	}
	if len(data) == offset {
		return true
	}
	if len(data)-offset < 2 {
		return false
	}
	offset += 2 // Optional capabilities.
	if !rsn || len(data) == offset {
		return len(data) == offset
	}
	if len(data)-offset < 2 {
		return false
	}
	count := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if count > (len(data)-offset)/16 {
		return false
	}
	offset += count * 16                                // Optional PMKIDs, never retained.
	return len(data) == offset || len(data)-offset == 4 // Group management cipher.
}
