package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// NetBIOSInfo holds decoded attributes from NetBIOS Name Service (NBNS / port 137)
type NetBIOSInfo struct {
	ComputerName string // <00> Unique Workstation name (e.g. "DESKTOP-ABC1234", "PC-SUZUKI")
	UserName     string // <03> Unique Messenger/User name (e.g. "SUZUKI", "HIROSHI", "TARO")
	Workgroup    string // <00> Group Domain/Workgroup name (e.g. "WORKGROUP", "CORP")
	ServerName   string // <20> Unique Server service name
	MACAddress   string // Hardware MAC address extracted from Unit ID
	IsWindows    bool   // True if host answered with valid NetBIOS node table
}

// QueryNetBIOSInfo sends a unicast NetBIOS Node Status query (NBSTAT) to target IP:137
func QueryNetBIOSInfo(ipStr string, timeout time.Duration) NetBIOSInfo {
	var info NetBIOSInfo
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(ipStr, "137"))
	if err != nil {
		return info
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return info
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// NetBIOS Node Status Query (RFC 1002) for wildcard "*" (CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
	query := []byte{
		0x80, 0x94, // Transaction ID
		0x00, 0x00, // Flags (Query, Broadcast=0)
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x20, // Length of encoded name (32 bytes)
		'C', 'K', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		0x00,       // Terminator
		0x00, 0x21, // Type: NBSTAT (33)
		0x00, 0x01, // Class: IN (1)
	}

	if _, err := conn.Write(query); err != nil {
		return info
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 56 {
		return info
	}

	return ParseNetBIOSNodeStatus(buf[:n])
}

// ParseNetBIOSNodeStatus parses the raw binary response from a NetBIOS Node Status query
func ParseNetBIOSNodeStatus(data []byte) NetBIOSInfo {
	var info NetBIOSInfo
	if len(data) < 56 {
		return info
	}

	// 1. Read DNS header
	qdCount := int(data[4])<<8 | int(data[5])
	anCount := int(data[6])<<8 | int(data[7])
	if anCount == 0 && qdCount == 0 {
		return info
	}

	offset := 12

	// 2. Skip Question section if qdCount > 0
	for q := 0; q < qdCount && offset < len(data); q++ {
		offset = skipDNSName(data, offset)
		offset += 4 // QTYPE(2) + QCLASS(2)
	}

	// 3. Process Answer section
	for a := 0; a < anCount && offset < len(data); a++ {
		offset = skipDNSName(data, offset)
		if offset+10 > len(data) {
			break
		}
		rrType := uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 10 // Type(2) + Class(2) + TTL(4) + RDLENGTH(2)

		if rrType == 0x0021 && offset < len(data) { // NBSTAT RR
			numNames := int(data[offset])
			offset++
			info.IsWindows = true

			for i := 0; i < numNames; i++ {
				entryOffset := offset + i*18
				if entryOffset+18 > len(data) {
					break
				}
				rawName := string(data[entryOffset : entryOffset+15])
				cleanName := strings.TrimRight(rawName, " \x00")
				suffix := data[entryOffset+15]
				flags := uint16(data[entryOffset+16])<<8 | uint16(data[entryOffset+17])
				isGroup := (flags & 0x8000) != 0

				switch suffix {
				case 0x00:
					if isGroup {
						if info.Workgroup == "" {
							info.Workgroup = cleanName
						}
					} else {
						if info.ComputerName == "" {
							info.ComputerName = cleanName
						}
					}
				case 0x03:
					if !isGroup && cleanName != "" && !strings.EqualFold(cleanName, info.ComputerName) {
						if info.UserName == "" {
							info.UserName = cleanName
						}
					}
				case 0x20:
					if !isGroup && info.ServerName == "" {
						info.ServerName = cleanName
					}
				case 0x1E, 0x1D:
					if isGroup && info.Workgroup == "" {
						info.Workgroup = cleanName
					}
				}
			}

			// Unit ID (MAC address): 6 bytes after the name table
			statsOffset := offset + numNames*18
			if statsOffset+6 <= len(data) {
				macBytes := data[statsOffset : statsOffset+6]
				if !isAllSameByte(macBytes, 0x00) && !isAllSameByte(macBytes, 0xFF) {
					info.MACAddress = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
						macBytes[0], macBytes[1], macBytes[2], macBytes[3], macBytes[4], macBytes[5])
				}
			}
			return info
		}
	}

	return info
}

func skipDNSName(data []byte, offset int) int {
	for offset < len(data) {
		lenByte := data[offset]
		if lenByte == 0 {
			return offset + 1
		}
		if (lenByte & 0xC0) == 0xC0 {
			return offset + 2 // 2-byte pointer
		}
		offset += 1 + int(lenByte)
	}
	return offset
}

func isAllSameByte(b []byte, v byte) bool {
	for _, x := range b {
		if x != v {
			return false
		}
	}
	return true
}

// DecodeNetBIOSName decodes a 32-character first-level encoded NetBIOS name (RFC 1002)
func DecodeNetBIOSName(encoded string) string {
	if len(encoded) < 32 {
		return ""
	}
	var decoded []byte
	for i := 0; i+1 < 32; i += 2 {
		c1 := encoded[i]
		c2 := encoded[i+1]
		if c1 < 'A' || c1 > 'P' || c2 < 'A' || c2 > 'P' {
			return ""
		}
		b := ((c1 - 'A') << 4) | (c2 - 'A')
		decoded = append(decoded, b)
	}
	if len(decoded) == 16 {
		// First 15 bytes are ASCII name, 16th is suffix
		namePart := strings.TrimRight(string(decoded[:15]), " \x00")
		return namePart
	}
	return ""
}

// ResolveWindowsModel maps UPnP/WSD manufacturer and model strings or NetBIOS hostnames into refined PC models
func ResolveWindowsModel(upnpModel, upnpName, hostname, vendor string) string {
	combined := fmt.Sprintf("%s %s %s %s", upnpModel, upnpName, hostname, vendor)
	combinedLower := strings.ToLower(combined)

	// Microsoft Surface Series
	if strings.Contains(combinedLower, "surface") {
		if strings.Contains(combinedLower, "pro 9") {
			return "Microsoft Surface Pro 9"
		} else if strings.Contains(combinedLower, "pro 8") {
			return "Microsoft Surface Pro 8"
		} else if strings.Contains(combinedLower, "pro 7") {
			return "Microsoft Surface Pro 7"
		} else if strings.Contains(combinedLower, "pro") {
			return "Microsoft Surface Pro"
		} else if strings.Contains(combinedLower, "laptop 5") {
			return "Microsoft Surface Laptop 5"
		} else if strings.Contains(combinedLower, "laptop 4") {
			return "Microsoft Surface Laptop 4"
		} else if strings.Contains(combinedLower, "laptop") {
			return "Microsoft Surface Laptop"
		} else if strings.Contains(combinedLower, "go") {
			return "Microsoft Surface Go"
		} else if strings.Contains(combinedLower, "studio") {
			return "Microsoft Surface Studio"
		}
		return "Microsoft Surface"
	}

	// Lenovo ThinkPad / IdeaPad
	if strings.Contains(combinedLower, "thinkpad") {
		if strings.Contains(combinedLower, "x1 carbon") {
			return "Lenovo ThinkPad X1 Carbon"
		} else if strings.Contains(combinedLower, "x1") {
			return "Lenovo ThinkPad X1 Series"
		} else if strings.Contains(combinedLower, "t14") {
			return "Lenovo ThinkPad T14"
		} else if strings.Contains(combinedLower, "t16") {
			return "Lenovo ThinkPad T16"
		} else if strings.Contains(combinedLower, "p1") || strings.Contains(combinedLower, "p14") || strings.Contains(combinedLower, "p16") {
			return "Lenovo ThinkPad P Series"
		} else if strings.Contains(combinedLower, "l13") || strings.Contains(combinedLower, "l14") || strings.Contains(combinedLower, "l15") {
			return "Lenovo ThinkPad L Series"
		} else if strings.Contains(combinedLower, "e14") || strings.Contains(combinedLower, "e15") || strings.Contains(combinedLower, "e16") {
			return "Lenovo ThinkPad E Series"
		}
		return "Lenovo ThinkPad"
	}

	// Panasonic Let's note
	if strings.Contains(combinedLower, "cf-sv") || strings.Contains(combinedLower, "cf-fv") || strings.Contains(combinedLower, "cf-sr") || strings.Contains(combinedLower, "cf-xz") || strings.Contains(combinedLower, "cf-lv") || strings.Contains(combinedLower, "let's note") || strings.Contains(combinedLower, "lets note") {
		if strings.Contains(combinedLower, "cf-sv") {
			return "Panasonic Let's note CF-SV Series"
		} else if strings.Contains(combinedLower, "cf-fv") {
			return "Panasonic Let's note CF-FV Series"
		} else if strings.Contains(combinedLower, "cf-sr") {
			return "Panasonic Let's note CF-SR Series"
		}
		return "Panasonic Let's note"
	}

	// Fujitsu LIFEBOOK
	if strings.Contains(combinedLower, "lifebook") || strings.Contains(combinedLower, "esprimo") {
		if strings.Contains(combinedLower, "u9311") || strings.Contains(combinedLower, "u9312") || strings.Contains(combinedLower, "u9313") {
			return "Fujitsu LIFEBOOK U9300 Series (Ultralight)"
		} else if strings.Contains(combinedLower, "u74") || strings.Contains(combinedLower, "u75") {
			return "Fujitsu LIFEBOOK U7000 Series"
		} else if strings.Contains(combinedLower, "a55") || strings.Contains(combinedLower, "a57") {
			return "Fujitsu LIFEBOOK A Series"
		} else if strings.Contains(combinedLower, "esprimo") {
			return "Fujitsu ESPRIMO Desktop PC"
		}
		return "Fujitsu LIFEBOOK"
	}

	// Dynabook / Toshiba
	if strings.Contains(combinedLower, "dynabook") {
		if strings.Contains(combinedLower, "g83") || strings.Contains(combinedLower, "rj74") || strings.Contains(combinedLower, "sj73") {
			return "Dynabook Business Mobile (G/RJ Series)"
		}
		return "Dynabook Notebook PC"
	}

	// Dell Latitude / OptiPlex / XPS / Precision
	if strings.Contains(combinedLower, "dell") || strings.Contains(combinedLower, "latitude") || strings.Contains(combinedLower, "optiplex") || strings.Contains(combinedLower, "xps") {
		if strings.Contains(combinedLower, "latitude") {
			return "Dell Latitude Laptop"
		} else if strings.Contains(combinedLower, "optiplex") {
			return "Dell OptiPlex Desktop"
		} else if strings.Contains(combinedLower, "xps") {
			return "Dell XPS"
		} else if strings.Contains(combinedLower, "precision") {
			return "Dell Precision Workstation"
		}
	}

	// HP EliteBook / ProBook / ZBook
	if strings.Contains(combinedLower, "hp") || strings.Contains(combinedLower, "elitebook") || strings.Contains(combinedLower, "probook") || strings.Contains(combinedLower, "zbook") {
		if strings.Contains(combinedLower, "elitebook") {
			return "HP EliteBook Laptop"
		} else if strings.Contains(combinedLower, "probook") {
			return "HP ProBook Laptop"
		} else if strings.Contains(combinedLower, "zbook") {
			return "HP ZBook Workstation"
		}
	}

	// VAIO
	if strings.Contains(combinedLower, "vaio") {
		if strings.Contains(combinedLower, "sx14") || strings.Contains(combinedLower, "sx12") {
			return "VAIO SX Series"
		} else if strings.Contains(combinedLower, "pro") {
			return "VAIO Pro Series"
		}
		return "VAIO PC"
	}

	// Mouse Computer
	if strings.Contains(combinedLower, "mousecomputer") || strings.Contains(combinedLower, "g-tune") || strings.Contains(combinedLower, "daiv") {
		if strings.Contains(combinedLower, "g-tune") {
			return "Mouse Computer G-Tune (Gaming PC)"
		} else if strings.Contains(combinedLower, "daiv") {
			return "Mouse Computer DAIV (Creator PC)"
		}
		return "Mouse Computer PC"
	}

	return ""
}
