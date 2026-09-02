//go:build !windows

package scanner

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Ping sends an ICMP echo request using an unprivileged datagram ICMP socket ("udp4")
func Ping(targetIP net.IP, timeout time.Duration) PingResult {
	result := PingResult{IP: targetIP, Alive: false}

	// Unprivileged datagram ICMP socket (Non-root, section 2.5)
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		if runtime.GOOS == "linux" {
			result.ErrorHint = "Unprivileged ICMP ping failed. Please run: 'sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"' or setcap 'cap_net_raw+ep'."
		} else {
			result.ErrorHint = fmt.Sprintf("Failed to open ICMP datagram socket: %v", err)
		}
		return result
	}
	defer c.Close()

	p := c.IPv4PacketConn()
	if p != nil {
		_ = p.SetControlMessage(ipv4.FlagTTL, true)
	}

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("LANMAP_PING"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return result
	}

	dst := &net.UDPAddr{IP: targetIP}
	start := time.Now()
	if err := c.SetDeadline(start.Add(timeout)); err != nil {
		return result
	}

	if _, err := c.WriteTo(wb, dst); err != nil {
		return result
	}

	rb := make([]byte, 1500)
	for {
		var n int
		var cm *ipv4.ControlMessage
		if p != nil {
			var err error
			n, cm, _, err = p.ReadFrom(rb)
			if err != nil {
				return result
			}
		} else {
			var err error
			n, _, err = c.ReadFrom(rb)
			if err != nil {
				return result
			}
		}
		rtt := time.Since(start)

		rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
		if err != nil {
			continue
		}

		if rm.Type == ipv4.ICMPTypeEchoReply {
			result.Alive = true
			result.RTT = rtt
			if cm != nil && cm.TTL > 0 {
				result.TTL = cm.TTL
			} else {
				result.TTL = 64
			}
			return result
		}
	}
}
