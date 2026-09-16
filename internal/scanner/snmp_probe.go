package scanner

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
)

// SNMPDeviceInfo holds sysName and sysDescr extracted via SNMP (UDP 161)
type SNMPDeviceInfo struct {
	SysName  string // Hostname / System Name
	SysDescr string // Hardware / OS Description
}

// QuerySNMPDeviceInfo probes target IP:161 with SNMP v2c/v1 GetRequest for sysName.0 and sysDescr.0
func QuerySNMPDeviceInfo(ipStr string, timeout time.Duration) *SNMPDeviceInfo {
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(ipStr, "161"))
	if err != nil {
		return nil
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// SNMPv2c GetRequest PDU for sysDescr.0 (1.3.6.1.2.1.1.1.0) and sysName.0 (1.3.6.1.2.1.1.5.0) with community "public"
	// 30 2f 02 01 01 (SNMPv2c) 04 06 "public" a0 22 02 04 <reqId> 02 01 00 02 01 00 30 14 30 08 06 08 2b 06 01 02 01 01 01 00 05 00 ...
	req := buildSNMPGetRequest("public", []string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"})
	if _, err := conn.Write(req); err != nil {
		return nil
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || n < 20 {
		return nil
	}

	return parseSNMPResponse(buf[:n])
}

func buildSNMPGetRequest(community string, oids []string) []byte {
	var varbindList bytes.Buffer
	for _, oidStr := range oids {
		oidBytes := encodeOID(oidStr)
		var vb bytes.Buffer
		vb.WriteByte(0x30) // Sequence
		vb.WriteByte(byte(len(oidBytes) + 2))
		vb.Write(oidBytes)
		vb.Write([]byte{0x05, 0x00}) // Null value
		varbindList.Write(vb.Bytes())
	}

	var pdu bytes.Buffer
	pdu.Write([]byte{
		0x02, 0x04, 0x12, 0x34, 0x56, 0x78, // Request ID
		0x02, 0x01, 0x00, // Error Status: 0
		0x02, 0x01, 0x00, // Error Index: 0
	})
	pdu.WriteByte(0x30) // Varbind list sequence
	pdu.WriteByte(byte(varbindList.Len()))
	pdu.Write(varbindList.Bytes())

	var getReq bytes.Buffer
	getReq.WriteByte(0xa0) // GetRequest PDU
	getReq.WriteByte(byte(pdu.Len()))
	getReq.Write(pdu.Bytes())

	var snmpMsg bytes.Buffer
	snmpMsg.Write([]byte{0x02, 0x01, 0x01}) // SNMP Version 2c (1)
	snmpMsg.WriteByte(0x04)                 // Octet String (community)
	snmpMsg.WriteByte(byte(len(community)))
	snmpMsg.WriteString(community)
	snmpMsg.Write(getReq.Bytes())

	var packet bytes.Buffer
	packet.WriteByte(0x30) // Message Sequence
	packet.WriteByte(byte(snmpMsg.Len()))
	packet.Write(snmpMsg.Bytes())

	return packet.Bytes()
}

func encodeOID(oidStr string) []byte {
	parts := strings.Split(strings.TrimPrefix(oidStr, "."), ".")
	if len(parts) < 2 {
		return nil
	}
	var nums []int
	for _, p := range parts {
		var n int
		fmt.Sscanf(p, "%d", &n)
		nums = append(nums, n)
	}
	if len(nums) < 2 {
		return nil
	}

	var encoded []byte
	encoded = append(encoded, byte(nums[0]*40+nums[1]))
	for _, n := range nums[2:] {
		if n < 128 {
			encoded = append(encoded, byte(n))
		} else {
			var b []byte
			for n > 0 {
				b = append([]byte{byte(n&0x7f | 0x80)}, b...)
				n >>= 7
			}
			b[len(b)-1] &= 0x7f
			encoded = append(encoded, b...)
		}
	}

	var res bytes.Buffer
	res.WriteByte(0x06) // OID Type
	res.WriteByte(byte(len(encoded)))
	res.Write(encoded)
	return res.Bytes()
}

func parseSNMPResponse(data []byte) *SNMPDeviceInfo {
	info := &SNMPDeviceInfo{}
	raw := string(data)

	// Extract readable strings
	var stringsFound []string
	idx := 0
	for idx < len(data) {
		if data[idx] == 0x04 && idx+1 < len(data) { // OCTET STRING
			strLen := int(data[idx+1])
			if idx+2+strLen <= len(data) && strLen > 0 {
				val := string(data[idx+2 : idx+2+strLen])
				if isCleanPrintableString(val) {
					stringsFound = append(stringsFound, val)
				}
				idx += 2 + strLen
				continue
			}
		}
		idx++
	}

	// First string is usually sysDescr, second is sysName
	for _, s := range stringsFound {
		if s == "public" {
			continue
		}
		if info.SysDescr == "" && len(s) > 10 {
			info.SysDescr = s
		} else if info.SysName == "" && len(s) <= 64 {
			info.SysName = s
		}
	}

	if info.SysName == "" && info.SysDescr == "" && len(raw) > 30 {
		return nil
	}
	return info
}
