//go:build windows

package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

var (
	modIphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

	procIcmpCreateFile  = modIphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = modIphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = modIphlpapi.NewProc("IcmpSendEcho")
)

type ipOptionInformation struct {
	TTL         byte
	Tos         byte
	Flags       byte
	OptionsSize byte
	OptionsData uintptr
}

type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

// Ping sends an ICMP echo using Win32 API IcmpSendEcho (non-admin, section 2.5)
func Ping(targetIP net.IP, timeout time.Duration) PingResult {
	result := PingResult{IP: targetIP, Alive: false}

	ipv4 := targetIP.To4()
	if ipv4 == nil {
		return result
	}

	hIcmp, _, err := procIcmpCreateFile.Call()
	if hIcmp == 0 || hIcmp == uintptr(syscall.InvalidHandle) {
		result.ErrorHint = fmt.Sprintf("IcmpCreateFile failed: %v", err)
		return result
	}
	defer procIcmpCloseHandle.Call(hIcmp)

	ipAddr := binary.LittleEndian.Uint32(ipv4)
	sendData := []byte("LANMAP_PING")
	replySize := uint32(unsafe.Sizeof(icmpEchoReply{}) + uintptr(len(sendData)) + 8)
	replyBuffer := make([]byte, replySize)

	timeoutMs := uint32(timeout.Milliseconds())
	if timeoutMs == 0 {
		timeoutMs = 1000
	}

	start := time.Now()
	ret, _, _ := procIcmpSendEcho.Call(
		hIcmp,
		uintptr(ipAddr),
		uintptr(unsafe.Pointer(&sendData[0])),
		uintptr(len(sendData)),
		0,
		uintptr(unsafe.Pointer(&replyBuffer[0])),
		uintptr(replySize),
		uintptr(timeoutMs),
	)

	if ret > 0 {
		reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuffer[0]))
		if reply.Status == 0 { // IP_SUCCESS
			result.Alive = true
			result.RTT = time.Since(start)
			result.TTL = int(reply.Options.TTL)
			return result
		}
	}

	return result
}
