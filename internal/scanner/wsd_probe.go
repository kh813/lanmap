package scanner

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// WSDDeviceInfo holds hardware and device metadata extracted from WS-Discovery (UDP 3702 / TCP 5357)
type WSDDeviceInfo struct {
	FriendlyName string // Computer or Device Name
	Manufacturer string // e.g. "Lenovo", "Microsoft Corporation", "Dell Inc."
	ModelName    string // e.g. "ThinkPad X1 Carbon Gen 10", "Surface Pro 9", "Latitude 5430"
	ModelNumber  string // e.g. "21CB000EJP"
	Types        string
}

var (
	reWSDModelName    = regexp.MustCompile(`(?i)<(?:wsd:|dp:)?ModelName[^>]*>([^<]+)</(?:wsd:|dp:)?ModelName>`)
	reWSDManufacturer = regexp.MustCompile(`(?i)<(?:wsd:|dp:)?Manufacturer[^>]*>([^<]+)</(?:wsd:|dp:)?Manufacturer>`)
	reWSDModelNumber  = regexp.MustCompile(`(?i)<(?:wsd:|dp:)?ModelNumber[^>]*>([^<]+)</(?:wsd:|dp:)?ModelNumber>`)
	reWSDFriendlyName = regexp.MustCompile(`(?i)<(?:wsd:|dp:)?FriendlyName[^>]*>([^<]+)</(?:wsd:|dp:)?FriendlyName>`)
)

// QueryWSDDeviceInfo probes target IP using WS-Discovery over UDP 3702 and WSD HTTP 5357
func QueryWSDDeviceInfo(ipStr string, timeout time.Duration) *WSDDeviceInfo {
	// 1. Unicast WS-Discovery Probe to UDP 3702
	if info := probeWSDUDP(ipStr, timeout); info != nil {
		return info
	}

	// 2. Direct HTTP probe to WSDAPI endpoint port 5357 / 5358
	return probeWSDHTTP(ipStr, timeout)
}

func probeWSDUDP(ipStr string, timeout time.Duration) *WSDDeviceInfo {
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(ipStr, "3702"))
	if err != nil {
		return nil
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	msgID := generateUUID()
	probeXML := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <soap:Header>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:%s</wsa:MessageID>
  </soap:Header>
  <soap:Body>
    <wsd:Probe>
      <wsd:Types>wsd:Device</wsd:Types>
    </wsd:Probe>
  </soap:Body>
</soap:Envelope>`, msgID)

	if _, err := conn.Write([]byte(probeXML)); err != nil {
		return nil
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 50 {
		return nil
	}

	return parseWSDXML(string(buf[:n]))
}

func probeWSDHTTP(ipStr string, timeout time.Duration) *WSDDeviceInfo {
	ports := []int{5357, 5358, 2869}
	client := &http.Client{
		Timeout: timeout,
	}

	for _, p := range ports {
		url := fmt.Sprintf("http://%s:%d/", ipStr, p)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Close = true
		req.Header.Set("User-Agent", "Mozilla/5.0 lanmap/0.0.44")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()

		if n > 0 {
			if info := parseWSDXML(string(buf[:n])); info != nil {
				return info
			}
		}
	}
	return nil
}

func parseWSDXML(body string) *WSDDeviceInfo {
	info := &WSDDeviceInfo{}
	found := false

	if m := reWSDModelName.FindStringSubmatch(body); len(m) >= 2 {
		info.ModelName = strings.TrimSpace(m[1])
		found = true
	}
	if m := reWSDManufacturer.FindStringSubmatch(body); len(m) >= 2 {
		info.Manufacturer = strings.TrimSpace(m[1])
		found = true
	}
	if m := reWSDModelNumber.FindStringSubmatch(body); len(m) >= 2 {
		info.ModelNumber = strings.TrimSpace(m[1])
		found = true
	}
	if m := reWSDFriendlyName.FindStringSubmatch(body); len(m) >= 2 {
		info.FriendlyName = strings.TrimSpace(m[1])
		found = true
	}

	if !found {
		return nil
	}
	return info
}

func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
