// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
)

type conversation struct{ source, target, protocol string }

// InspectCapture reads classic PCAP and Ethernet frames. PCAPNG users can
// export classic PCAP or TShark JSON; unsupported formats fail explicitly.
func InspectCapture(data []byte) (*Report, error) {
	if err := checkInput(data); err != nil {
		return nil, err
	}
	if len(data) < 24 {
		return nil, fmt.Errorf("truncated PCAP global header")
	}
	var order binary.ByteOrder
	switch binary.BigEndian.Uint32(data[:4]) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		order = binary.BigEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		order = binary.LittleEndian
	case 0x0a0d0d0a:
		return nil, fmt.Errorf("PCAPNG is not supported; export classic Ethernet PCAP or TShark JSON in Wireshark")
	default:
		return nil, fmt.Errorf("not a supported classic PCAP file")
	}
	if order.Uint16(data[4:6]) != 2 || order.Uint16(data[6:8]) != 4 {
		return nil, fmt.Errorf("unsupported PCAP version")
	}
	if order.Uint32(data[20:24])&0xffff != 1 {
		return nil, fmt.Errorf("only Ethernet PCAP link type 1 is supported")
	}
	r := newReport("pcap", "Offline Ethernet packet metadata and conversation summary.", data)
	counts := map[conversation]int{}
	packets, skipped := 0, 0
	for offset := 24; offset < len(data); {
		if len(data)-offset < 16 {
			return nil, fmt.Errorf("truncated PCAP packet header")
		}
		captured := uint64(order.Uint32(data[offset+8 : offset+12]))
		original := uint64(order.Uint32(data[offset+12 : offset+16]))
		offset += 16
		if captured > uint64(len(data)-offset) || captured > original {
			return nil, fmt.Errorf("invalid PCAP packet length")
		}
		frame := data[offset : offset+int(captured)]
		offset += int(captured)
		packets++
		if packets > 100000 {
			r.Limited = true
			r.gap("Packet analysis stopped at 100,000 packets.")
			break
		}
		if captured < original {
			r.gap("The capture contains truncated packets.")
		}
		c, ok := ethernetConversation(frame)
		if !ok {
			skipped++
			continue
		}
		if _, exists := counts[c]; !exists && len(counts) >= maxRecords {
			r.limit()
			continue
		}
		counts[c]++
	}
	keys := make([]conversation, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i].source+keys[i].target+keys[i].protocol < keys[j].source+keys[j].target+keys[j].protocol
	})
	r.observe("packets", "capture", fmt.Sprintf("%d frames · %d unsupported or incomplete frames", packets, skipped))
	for _, key := range keys {
		r.observe(key.protocol, key.source+" → "+key.target, fmt.Sprintf("%d packets", counts[key]))
		r.edge(r.node("endpoint", key.source), r.node("endpoint", key.target), key.protocol)
	}
	if skipped > 0 {
		r.gap("Non-IP, unsupported or malformed frames were omitted from conversation analysis.")
	}
	r.gap("Packet metadata only. No live capture, payload decoding, TLS decryption, TCP reassembly or wireless monitor mode. IPv6 extension headers and fragmented transport ports are not decoded.")
	return r, nil
}

func ethernetConversation(frame []byte) (conversation, bool) {
	if len(frame) < 14 {
		return conversation{}, false
	}
	kind := binary.BigEndian.Uint16(frame[12:14])
	ipOffset := 14
	for tags := 0; kind == 0x8100 || kind == 0x88a8; tags++ {
		if tags >= 2 || len(frame) < ipOffset+4 {
			return conversation{}, false
		}
		kind = binary.BigEndian.Uint16(frame[ipOffset+2 : ipOffset+4])
		ipOffset += 4
	}
	ip := frame[ipOffset:]
	var source, target netip.Addr
	var protocol byte
	var transport []byte
	switch kind {
	case 0x0800:
		if len(ip) < 20 || ip[0]>>4 != 4 {
			return conversation{}, false
		}
		header := int(ip[0]&15) * 4
		total := int(binary.BigEndian.Uint16(ip[2:4]))
		if header < 20 || total < header || len(ip) < header {
			return conversation{}, false
		}
		source = netip.AddrFrom4([4]byte(ip[12:16]))
		target = netip.AddrFrom4([4]byte(ip[16:20]))
		protocol = ip[9]
		end := min(total, len(ip))
		if binary.BigEndian.Uint16(ip[6:8])&0x1fff == 0 {
			transport = ip[header:end]
		}
	case 0x86dd:
		if len(ip) < 40 || ip[0]>>4 != 6 {
			return conversation{}, false
		}
		source = netip.AddrFrom16([16]byte(ip[8:24]))
		target = netip.AddrFrom16([16]byte(ip[24:40]))
		protocol = ip[6]
		end := min(40+int(binary.BigEndian.Uint16(ip[4:6])), len(ip))
		transport = ip[40:end]
	default:
		return conversation{}, false
	}
	c := conversation{source: source.String(), target: target.String(), protocol: fmt.Sprintf("IP protocol %d", protocol)}
	if protocol == 6 || protocol == 17 {
		if protocol == 6 {
			c.protocol = "TCP"
		} else {
			c.protocol = "UDP"
		}
		if len(transport) >= 4 {
			c.source = netip.AddrPortFrom(source, binary.BigEndian.Uint16(transport[:2])).String()
			c.target = netip.AddrPortFrom(target, binary.BigEndian.Uint16(transport[2:4])).String()
		}
	} else if protocol == 1 || protocol == 58 {
		c.protocol = "ICMP"
	}
	return c, true
}
