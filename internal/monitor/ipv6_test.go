package monitor

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseDHCPv6Packet(t *testing.T) {
	// Construct synthetic DHCPv6 Request packet
	var buf []byte

	// Header: MsgType=1 (Solicit), XID=0x123456
	buf = append(buf, 1, 0x12, 0x34, 0x56)

	// Option 1: Client ID with DUID-LL (type 3, ethernet hw 1, mac 00:11:22:33:44:55)
	opt1 := make([]byte, 4+10)
	binary.BigEndian.PutUint16(opt1[0:2], 1)  // code = 1
	binary.BigEndian.PutUint16(opt1[2:4], 10) // len = 10
	binary.BigEndian.PutUint16(opt1[4:6], 3)  // DUID-LL
	binary.BigEndian.PutUint16(opt1[6:8], 1)  // Ethernet
	copy(opt1[8:14], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	buf = append(buf, opt1...)

	// Option 3: IA_NA with sub-option 5 IAADDR (2001:db8::1234)
	iaAddr := net.ParseIP("2001:db8::1234")
	subOpt := make([]byte, 4+24)
	binary.BigEndian.PutUint16(subOpt[0:2], 5)  // code = 5 (IAADDR)
	binary.BigEndian.PutUint16(subOpt[2:4], 24) // len = 24
	copy(subOpt[4:20], iaAddr.To16())
	binary.BigEndian.PutUint32(subOpt[20:24], 3600)
	binary.BigEndian.PutUint32(subOpt[24:28], 7200)

	opt3Len := 12 + len(subOpt)
	opt3 := make([]byte, 4+12)
	binary.BigEndian.PutUint16(opt3[0:2], 3)
	binary.BigEndian.PutUint16(opt3[2:4], uint16(opt3Len))
	// IAID, T1, T2
	copy(opt3[4:16], make([]byte, 12))
	buf = append(buf, opt3...)
	buf = append(buf, subOpt...)

	// Option 39: FQDN ("my-host.lan")
	fqdnData := []byte{0x00, 0x07, 'm', 'y', '-', 'h', 'o', 's', 't', 0x03, 'l', 'a', 'n', 0x00}
	opt39 := make([]byte, 4)
	binary.BigEndian.PutUint16(opt39[0:2], 39)
	binary.BigEndian.PutUint16(opt39[2:4], uint16(len(fqdnData)))
	buf = append(buf, opt39...)
	buf = append(buf, fqdnData...)

	pkt, err := ParseDHCPv6Packet(buf)
	if err != nil {
		t.Fatalf("ParseDHCPv6Packet failed: %v", err)
	}

	if pkt.MessageType != 1 {
		t.Errorf("MessageType = %d; want 1", pkt.MessageType)
	}
	if pkt.ClientMAC != "00:11:22:33:44:55" {
		t.Errorf("ClientMAC = %s; want 00:11:22:33:44:55", pkt.ClientMAC)
	}
	if pkt.AssignedIP == nil || !pkt.AssignedIP.Equal(iaAddr) {
		t.Errorf("AssignedIP = %v; want %v", pkt.AssignedIP, iaAddr)
	}
	if pkt.Hostname != "my-host.lan" {
		t.Errorf("Hostname = %s; want my-host.lan", pkt.Hostname)
	}
}
