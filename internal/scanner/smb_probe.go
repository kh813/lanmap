package scanner

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf16"
)

// SMBDeviceInfo holds host attributes decoded anonymously via SMB2/NTLMSSP negotiation
type SMBDeviceInfo struct {
	ComputerName string // NetBIOS Computer Name (e.g. "THINKPAD-X1", "DESKTOP-ABC1234")
	DNSHostName  string // DNS Computer / Host Name (e.g. "thinkpad-x1.lan")
	DomainName   string // NetBIOS Domain / Workgroup (e.g. "WORKGROUP", "CORP")
	DNSDomain    string // DNS Domain Name
	OSVersion    string // Formatted OS version from NTLMSSP (e.g. "Windows 11 / 10 (Build 22631)")
	IsWindows    bool
}

// QuerySMBDeviceInfo probes TCP 445 and retrieves computer name, domain, and OS build using anonymous NTLMSSP negotiation
func QuerySMBDeviceInfo(ipStr string, timeout time.Duration) SMBDeviceInfo {
	var info SMBDeviceInfo
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ipStr, "445"), timeout)
	if err != nil {
		return info
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// 1. Send SMB2 Negotiate Protocol Request
	negReq := buildSMB2NegotiateRequest()
	if _, err := conn.Write(negReq); err != nil {
		return info
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 68 {
		return info
	}

	// Verify SMB2 Header (\xfeSMB)
	if !bytes.Equal(buf[4:8], []byte("\xfeSMB")) {
		return info
	}

	info.IsWindows = true

	// 2. Send SMB2 Session Setup Request with NTLMSSP Negotiate (Type 1)
	sessionReq := buildSMB2SessionSetupNTLMRequest()
	if _, err := conn.Write(sessionReq); err != nil {
		return info
	}

	n, err = conn.Read(buf)
	if err != nil || n < 68 {
		return info
	}

	// 3. Find NTLMSSP Challenge (Type 2) in response
	ntlmIdx := bytes.Index(buf[:n], []byte("NTLMSSP\x00"))
	if ntlmIdx == -1 {
		return info
	}

	return parseNTLMSSPType2(buf[ntlmIdx:n], info)
}

func buildSMB2NegotiateRequest() []byte {
	// NetBIOS Session Header + SMB2 Header (64 bytes) + SMB2 Negotiate Request (36 bytes)
	var pkt bytes.Buffer

	// NetBIOS Session Header (4 bytes): length = 100
	pkt.Write([]byte{0x00, 0x00, 0x00, 0x64})

	// SMB2 Header
	pkt.Write([]byte{
		0xfe, 'S', 'M', 'B', // Protocol ID
		0x40, 0x00, // StructureSize = 64
		0x00, 0x00, // CreditCharge
		0x00, 0x00, 0x00, 0x00, // Status
		0x00, 0x00, // Command: NEGOTIATE (0)
		0x00, 0x00, // Credits requested
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // NextCommand
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageID
		0x00, 0x00, 0x00, 0x00, // ProcessID
		0x00, 0x00, 0x00, 0x00, // TreeID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (16 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	// SMB2 Negotiate Request Payload (36 bytes)
	pkt.Write([]byte{
		0x24, 0x00, // StructureSize = 36
		0x02, 0x00, // DialectCount = 2
		0x01, 0x00, // SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED
		0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // ClientGUID (16 bytes)
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientStartTime
		0x02, 0x02, // Dialect: SMB 2.0.2
		0x10, 0x02, // Dialect: SMB 2.1
	})

	return pkt.Bytes()
}

func buildSMB2SessionSetupNTLMRequest() []byte {
	// NTLMSSP Negotiate Message (Type 1)
	ntlmType1 := []byte{
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
		0x01, 0x00, 0x00, 0x00, // Type 1
		0x05, 0xb2, 0x08, 0xa2, // Flags: Negotiate Unicode, OEM, NTLM, Request Target, Extended Security, Target Info
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Domain info
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Workstation info
		0x0a, 0x00, 0x61, 0x4a, 0x00, 0x00, 0x00, 0x0f, // Version: Windows 10/11
	}

	// Security Buffer offset in SMB2 Session Setup is at byte 88 (64 header + 24 setup struct)
	secBufferOffset := uint16(88)
	secBufferLen := uint16(len(ntlmType1))
	totalLen := 64 + 24 + len(ntlmType1)

	var pkt bytes.Buffer
	// NetBIOS Session Header
	nbHdr := make([]byte, 4)
	binary.BigEndian.PutUint32(nbHdr, uint32(totalLen))
	pkt.Write(nbHdr)

	// SMB2 Header
	pkt.Write([]byte{
		0xfe, 'S', 'M', 'B', // Protocol ID
		0x40, 0x00, // StructureSize = 64
		0x00, 0x00, // CreditCharge
		0x00, 0x00, 0x00, 0x00, // Status
		0x01, 0x00, // Command: SESSION_SETUP (1)
		0x00, 0x00, // Credits requested
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // NextCommand
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageID = 1
		0x00, 0x00, 0x00, 0x00, // ProcessID
		0x00, 0x00, 0x00, 0x00, // TreeID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	// SMB2 Session Setup Payload (24 bytes)
	setupPayload := make([]byte, 24)
	setupPayload[0] = 0x19 // StructureSize = 25
	setupPayload[1] = 0x00
	setupPayload[2] = 0x00 // Flags
	setupPayload[3] = 0x00 // SecurityMode
	binary.LittleEndian.PutUint16(setupPayload[4:6], 0)
	binary.LittleEndian.PutUint16(setupPayload[6:8], 0)
	binary.LittleEndian.PutUint16(setupPayload[8:10], 0)
	binary.LittleEndian.PutUint16(setupPayload[10:12], 0)
	binary.LittleEndian.PutUint16(setupPayload[12:14], secBufferOffset)
	binary.LittleEndian.PutUint16(setupPayload[14:16], secBufferLen)
	binary.LittleEndian.PutUint64(setupPayload[16:24], 0) // PreviousSessionID

	pkt.Write(setupPayload)
	pkt.Write(ntlmType1)

	return pkt.Bytes()
}

func parseNTLMSSPType2(data []byte, info SMBDeviceInfo) SMBDeviceInfo {
	if len(data) < 48 || !bytes.Equal(data[:8], []byte("NTLMSSP\x00")) {
		return info
	}

	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != 2 { // NTLMSSP Challenge (Type 2)
		return info
	}

	// Target Info Fields: [Len(2)][MaxLen(2)][Offset(4)] at offset 40
	if len(data) >= 48 {
		tiLen := int(binary.LittleEndian.Uint16(data[40:42]))
		tiOffset := int(binary.LittleEndian.Uint32(data[44:48]))

		if tiOffset+tiLen <= len(data) && tiOffset > 0 {
			targetInfo := data[tiOffset : tiOffset+tiLen]
			info = parseAVPairs(targetInfo, info)
		}
	}

	// OS Version: [Major(1)][Minor(1)][Build(2)][Reserved(3)][NTLMRev(1)] at offset 48
	if len(data) >= 56 {
		major := data[48]
		minor := data[49]
		build := binary.LittleEndian.Uint16(data[50:52])
		if major > 0 {
			if major == 10 && minor == 0 {
				if build >= 22000 {
					info.OSVersion = fmt.Sprintf("Windows 11 (Build %d)", build)
				} else {
					info.OSVersion = fmt.Sprintf("Windows 10 (Build %d)", build)
				}
			} else if major == 6 {
				switch minor {
				case 3:
					info.OSVersion = "Windows 8.1 / Server 2012 R2"
				case 2:
					info.OSVersion = "Windows 8 / Server 2012"
				case 1:
					info.OSVersion = "Windows 7 / Server 2008 R2"
				case 0:
					info.OSVersion = "Windows Vista / Server 2008"
				}
			} else {
				info.OSVersion = fmt.Sprintf("Windows NT %d.%d (Build %d)", major, minor, build)
			}
		}
	}

	return info
}

func parseAVPairs(data []byte, info SMBDeviceInfo) SMBDeviceInfo {
	offset := 0
	for offset+4 <= len(data) {
		avID := binary.LittleEndian.Uint16(data[offset : offset+2])
		avLen := int(binary.LittleEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if avID == 0x0000 { // MsvAvEOL (End of List)
			break
		}

		if offset+avLen > len(data) {
			break
		}

		valBytes := data[offset : offset+avLen]
		valStr := decodeUTF16LE(valBytes)
		offset += avLen

		switch avID {
		case 0x0001: // MsvAvNbComputerName
			if info.ComputerName == "" {
				info.ComputerName = valStr
			}
		case 0x0002: // MsvAvNbDomainName
			if info.DomainName == "" {
				info.DomainName = valStr
			}
		case 0x0003: // MsvAvDnsComputerName
			if info.DNSHostName == "" {
				info.DNSHostName = valStr
			}
		case 0x0004: // MsvAvDnsDomainName
			if info.DNSDomain == "" {
				info.DNSDomain = valStr
			}
		}
	}
	return info
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	runes := utf16.Decode(u16)
	return strings.TrimSpace(string(runes))
}
