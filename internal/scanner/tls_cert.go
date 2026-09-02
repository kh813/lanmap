package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// TLSCertInfo contains parsed TLS certificate metadata
type TLSCertInfo struct {
	Subject string
	Expiry  time.Time
}

// InspectTLSCert connects to HTTPS port on host and extracts X.509 certificate info
func InspectTLSCert(ip string) *TLSCertInfo {
	ports := []int{443, 8443, 5001}

	dialer := &net.Dialer{
		Timeout: 350 * time.Millisecond,
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	for _, port := range ports {
		addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
		if err != nil {
			continue
		}
		defer conn.Close()

		state := conn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			subject := cert.Subject.CommonName
			if subject == "" && len(cert.DNSNames) > 0 {
				subject = cert.DNSNames[0]
			}
			if subject == "" && len(cert.IPAddresses) > 0 {
				subject = cert.IPAddresses[0].String()
			}
			if subject == "" && cert.Subject.Organization != nil && len(cert.Subject.Organization) > 0 {
				subject = strings.Join(cert.Subject.Organization, ", ")
			}

			return &TLSCertInfo{
				Subject: subject,
				Expiry:  cert.NotAfter,
			}
		}
	}

	return nil
}
