package db

import (
	"database/sql"
	"fmt"
	"html/template"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortInfo represents a detected open port, service name, and security severity
type PortInfo struct {
	Port       int    `json:"port"`
	Service    string `json:"service"`
	Severity   string `json:"severity"` // "info", "warning", "danger"
	Icon       string `json:"icon"`     // "ℹ️", "⚠️", "🚨"
	BadgeClass string `json:"badge_class"`
	DotClass   string `json:"dot_class"`
}

// Host represents a discovered or monitored network host
type Host struct {
	ID               int64         `json:"id"`
	IP               string        `json:"ip"`
	SegmentID        *int64        `json:"segment_id"`
	MACAddress       string        `json:"mac_address"`
	Hostname         string        `json:"hostname"`
	VendorModel      string        `json:"vendor_model"`
	DisplayName      string        `json:"display_name"`
	OSVendor         string        `json:"os_vendor"`
	Status           string        `json:"status"`
	PingRTTMs        *float64      `json:"ping_rtt_ms"`
	PingJitterMs     *float64      `json:"ping_jitter_ms"`
	UptimePct        float64       `json:"uptime_pct"`
	OpenPorts        string        `json:"open_ports"`
	HTTPTitle        string        `json:"http_title"`
	UPnPName         string        `json:"upnp_name"`
	UPnPModel        string        `json:"upnp_model"`
	UPnPSerial       string        `json:"upnp_serial"`
	TLSSubject       string        `json:"tls_subject"`
	TLSExpiry        *time.Time    `json:"tls_expiry"`
	MDNSModel        string        `json:"mdns_model"`
	BroadcastCount1m int           `json:"broadcast_count_1m"`
	IsStorming       bool          `json:"is_storming"`
	IsApproved       bool          `json:"is_approved"`
	IsProtected      bool          `json:"is_protected"`
	IsStaticIP       bool          `json:"is_static_ip"`
	IsDHCP           bool          `json:"is_dhcp"`
	IsMonitored      bool          `json:"is_monitored"`
	IsPaused         bool          `json:"is_paused"`
	HasConflict      bool          `json:"has_conflict"`
	KumaName         string        `json:"kuma_name"`
	UptimeKumaID     *int64        `json:"uptime_kuma_id"`
	FirstSeen        time.Time     `json:"first_seen"`
	LastSeen         *time.Time    `json:"last_seen"`
	LastPortScan     *time.Time    `json:"last_port_scan"`
	NextPortScan     *time.Time    `json:"next_port_scan"`
	IgnoredPorts     string        `json:"ignored_ports"`
	AgentID          *string       `json:"agent_id"`
	AgentName        string        `json:"agent_name"`
	IPv6Addresses    string        `json:"ipv6_addresses"`
	IsPreviousHost   bool          `json:"-"`
	PingChartSVG     template.HTML `json:"-"`
	UptimeBlocksSVG  template.HTML `json:"-"`
	PingStats7d      string        `json:"-"`
}

// RiskBadge represents a visual security risk indicator for ports
type RiskBadge struct {
	Level      string // "critical", "warning", "info", "suppressed"
	Label      string
	Port       int
	Service    string
	BadgeClass string
}

// ServiceBadge represents a visual informational badge for recognized services
type ServiceBadge struct {
	Label      string
	Port       int
	Service    string
	BadgeClass string
}

// IPv6Type represents the classification of an IPv6 address
type IPv6Type string

const (
	IPv6TypeLLA   IPv6Type = "LLA"   // Link-Local Address (fe80::/10)
	IPv6TypeGUA   IPv6Type = "GUA"   // Global Unicast Address (2000::/3)
	IPv6TypeULA   IPv6Type = "ULA"   // Unique Local Address (fc00::/7)
	IPv6TypeOther IPv6Type = "Other" // Multicast, Loopback, Unspecified, etc.
)

// IPv6Info represents a structured IPv6 address associated with a host
type IPv6Info struct {
	Address    string   `json:"address"`
	Type       IPv6Type `json:"type"`
	TypeDesc   string   `json:"type_desc"`
	BadgeClass string   `json:"badge_class"`
}

func isIPv4(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	return ip != nil && ip.To4() != nil
}

func isIPv6(ipStr string) bool {
	clean := strings.TrimSpace(ipStr)
	if idx := strings.Index(clean, "%"); idx != -1 {
		clean = clean[:idx]
	}
	ip := net.ParseIP(clean)
	return ip != nil && ip.To4() == nil
}

// ClassifyIPv6 inspects an IPv6 address string and returns its type and human-readable metadata.
func ClassifyIPv6(addrStr string) IPv6Info {
	clean := strings.TrimSpace(addrStr)
	ipOnly := clean
	if idx := strings.Index(ipOnly, "%"); idx != -1 {
		ipOnly = ipOnly[:idx]
	}

	ip := net.ParseIP(ipOnly)
	if ip == nil || ip.To4() != nil {
		return IPv6Info{
			Address:    clean,
			Type:       IPv6TypeOther,
			TypeDesc:   "その他 / IPv4",
			BadgeClass: "bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700",
		}
	}

	if ip.IsLinkLocalUnicast() {
		return IPv6Info{
			Address:    clean,
			Type:       IPv6TypeLLA,
			TypeDesc:   "リンクローカル (fe80::)",
			BadgeClass: "bg-purple-100 text-purple-800 border-purple-300 dark:bg-purple-950/70 dark:text-purple-300 dark:border-purple-800",
		}
	}

	// ULA is fc00::/7
	if (ip[0] & 0xfe) == 0xfc {
		return IPv6Info{
			Address:    clean,
			Type:       IPv6TypeULA,
			TypeDesc:   "ユニークローカル (fc00::)",
			BadgeClass: "bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/70 dark:text-amber-300 dark:border-amber-800",
		}
	}

	// GUA is 2000::/3 (ip[0] & 0xe0 == 0x20)
	if (ip[0] & 0xe0) == 0x20 {
		return IPv6Info{
			Address:    clean,
			Type:       IPv6TypeGUA,
			TypeDesc:   "グローバル (2000::)",
			BadgeClass: "bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950/70 dark:text-blue-300 dark:border-blue-800",
		}
	}

	return IPv6Info{
		Address:    clean,
		Type:       IPv6TypeOther,
		TypeDesc:   "その他 IPv6",
		BadgeClass: "bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700",
	}
}

// mergeIPv6Addresses combines multiple comma-separated or single IPv6 address strings,
// deduplicating them and sorting with priority: GUA (2000::/3), ULA (fc00::/7), LLA (fe80::/10), others.
func mergeIPv6Addresses(addrs ...string) string {
	seen := make(map[string]bool)
	var list []string

	for _, addrStr := range addrs {
		if addrStr == "" {
			continue
		}
		for _, part := range strings.Split(addrStr, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			clean := trimmed
			if idx := strings.Index(clean, "%"); idx != -1 {
				clean = clean[:idx]
			}
			ip := net.ParseIP(clean)
			if ip == nil || ip.To4() != nil {
				continue
			}
			canonical := strings.ToLower(ip.String())
			if !seen[canonical] {
				seen[canonical] = true
				list = append(list, canonical)
			}
		}
	}

	sort.SliceStable(list, func(i, j int) bool {
		ti := ClassifyIPv6(list[i]).Type
		tj := ClassifyIPv6(list[j]).Type
		order := map[IPv6Type]int{
			IPv6TypeGUA:   1,
			IPv6TypeULA:   2,
			IPv6TypeLLA:   3,
			IPv6TypeOther: 4,
		}
		if order[ti] != order[tj] {
			return order[ti] < order[tj]
		}
		return list[i] < list[j]
	})

	return strings.Join(list, ", ")
}

// MergeIPv6Addresses combines multiple comma-separated or single IPv6 address strings,
// deduplicating them and sorting with priority: GUA (2000::/3), ULA (fc00::/7), LLA (fe80::/10), others.
func MergeIPv6Addresses(addrs ...string) string {
	return mergeIPv6Addresses(addrs...)
}

// GetIPv6List returns parsed and classified IPv6 addresses associated with this host
func (h *Host) GetIPv6List() []IPv6Info {
	var list []string
	if h.IPv6Addresses != "" {
		for _, p := range strings.Split(h.IPv6Addresses, ",") {
			t := strings.TrimSpace(p)
			if t != "" {
				list = append(list, t)
			}
		}
	}
	// If primary IP is pure IPv6 and not in list, include it
	if isIPv6(h.IP) {
		cleanPrimary := strings.TrimSpace(h.IP)
		found := false
		for _, s := range list {
			if strings.EqualFold(s, cleanPrimary) {
				found = true
				break
			}
		}
		if !found && cleanPrimary != "" {
			list = append([]string{cleanPrimary}, list...)
		}
	}

	var res []IPv6Info
	seen := make(map[string]bool)
	for _, addr := range list {
		clean := strings.ToLower(strings.TrimSpace(addr))
		if clean == "" || seen[clean] {
			continue
		}
		seen[clean] = true
		res = append(res, ClassifyIPv6(addr))
	}
	return res
}

// HasIPv6 returns true if the host has any IPv6 addresses or primary IP is IPv6
func (h *Host) HasIPv6() bool {
	if strings.TrimSpace(h.IPv6Addresses) != "" {
		return true
	}
	return isIPv6(h.IP)
}

// IsPureIPv6 returns true if primary IP is IPv6 (i.e. no IPv4 address)
func (h *Host) IsPureIPv6() bool {
	return isIPv6(h.IP)
}

// PrimaryLinkLocalIPv6 returns the primary link-local (fe80::) address if available
func (h *Host) PrimaryLinkLocalIPv6() string {
	for _, info := range h.GetIPv6List() {
		if info.Type == IPv6TypeLLA {
			return info.Address
		}
	}
	return ""
}

// PrimaryIPv6 returns the preferred IPv6 address (GUA preferred, then ULA, then LLA)
func (h *Host) PrimaryIPv6() string {
	list := h.GetIPv6List()
	for _, info := range list {
		if info.Type == IPv6TypeGUA {
			return info.Address
		}
	}
	for _, info := range list {
		if info.Type == IPv6TypeULA {
			return info.Address
		}
	}
	for _, info := range list {
		if info.Type == IPv6TypeLLA {
			return info.Address
		}
	}
	if len(list) > 0 {
		return list[0].Address
	}
	return ""
}

// IsPortIgnored returns true if the port is in the host's ignored/suppressed ports list
func (h *Host) IsPortIgnored(port int) bool {
	if h.IgnoredPorts == "" {
		return false
	}
	for _, part := range strings.Split(h.IgnoredPorts, ",") {
		val, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil && val == port {
			return true
		}
	}
	return false
}

// IgnoredPortsList returns list of integer port numbers whose warnings are suppressed
func (h *Host) IgnoredPortsList() []int {
	var list []int
	if h.IgnoredPorts == "" {
		return list
	}
	for _, part := range strings.Split(h.IgnoredPorts, ",") {
		val, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil {
			list = append(list, val)
		}
	}
	sort.Ints(list)
	return list
}

// SecurityRiskBadges returns any security risk badges identified on open ports, excluding suppressed ports
func (h *Host) SecurityRiskBadges() []RiskBadge {
	var badges []RiskBadge
	for _, p := range h.OpenPortsList() {
		if h.IsPortIgnored(p.Port) {
			continue
		}
		switch p.Port {
		case 1194, 1723, 5555:
			badges = append(badges, RiskBadge{
				Level:      "critical",
				Label:      "🚨 VPN (" + p.Service + ")",
				Port:       p.Port,
				Service:    p.Service,
				BadgeClass: "bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-950/70 dark:text-rose-300 dark:border-rose-800",
			})
		case 5938:
			badges = append(badges, RiskBadge{
				Level:      "critical",
				Label:      "🚨 TeamViewer",
				Port:       p.Port,
				Service:    p.Service,
				BadgeClass: "bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-950/70 dark:text-rose-300 dark:border-rose-800",
			})
		case 7070:
			badges = append(badges, RiskBadge{
				Level:      "critical",
				Label:      "🚨 AnyDesk",
				Port:       p.Port,
				Service:    p.Service,
				BadgeClass: "bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-950/70 dark:text-rose-300 dark:border-rose-800",
			})
		case 3389, 5900:
			badges = append(badges, RiskBadge{
				Level:      "warning",
				Label:      "⚠️ " + p.Service,
				Port:       p.Port,
				Service:    p.Service,
				BadgeClass: "bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/70 dark:text-amber-300 dark:border-amber-800",
			})
		case 23:
			badges = append(badges, RiskBadge{
				Level:      "warning",
				Label:      "⚠️ Telnet",
				Port:       p.Port,
				Service:    p.Service,
				BadgeClass: "bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-950/70 dark:text-orange-300 dark:border-orange-800",
			})
		}
	}
	return badges
}

// SuppressedRiskBadges returns open ports that would normally be security risks but have been suppressed
func (h *Host) SuppressedRiskBadges() []RiskBadge {
	var badges []RiskBadge
	for _, p := range h.OpenPortsList() {
		if !h.IsPortIgnored(p.Port) {
			continue
		}
		switch p.Port {
		case 1194, 1723, 5555, 5938, 7070, 3389, 5900, 23:
			badges = append(badges, RiskBadge{
				Level:      "suppressed",
				Label:      "🛡️ " + p.Service + " (既知・警告抑止中)",
				Port:       p.Port,
				Service:    p.Service,
				BadgeClass: "bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700",
			})
		}
	}
	return badges
}

// HasSuppressedRisks returns true if the host has any suppressed risk ports
func (h *Host) HasSuppressedRisks() bool {
	return len(h.SuppressedRiskBadges()) > 0
}

// HasSecurityRisk returns true if the host has unsuppressed critical or warning open ports
func (h *Host) HasSecurityRisk() bool {
	return len(h.SecurityRiskBadges()) > 0
}

// ServiceInfoBadges returns high-value informational service badges for recognized normal ports
func (h *Host) ServiceInfoBadges() []ServiceBadge {
	var badges []ServiceBadge
	seenCategories := make(map[string]bool)

	for _, p := range h.OpenPortsList() {
		switch p.Port {
		case 22:
			if !seenCategories["ssh"] {
				seenCategories["ssh"] = true
				badges = append(badges, ServiceBadge{
					Label:      "🔑 SSH",
					Port:       p.Port,
					Service:    "SSH",
					BadgeClass: "bg-sky-100 text-sky-800 border-sky-300 dark:bg-sky-950/70 dark:text-sky-300 dark:border-sky-800",
				})
			}
		case 80, 443:
			if !seenCategories["web"] {
				seenCategories["web"] = true
				badges = append(badges, ServiceBadge{
					Label:      "🌐 Web",
					Port:       p.Port,
					Service:    p.Service,
					BadgeClass: "bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950/70 dark:text-blue-300 dark:border-blue-800",
				})
			}
		case 8080, 8443:
			if !seenCategories["web_alt"] {
				seenCategories["web_alt"] = true
				badges = append(badges, ServiceBadge{
					Label:      "🌐 Web-Alt",
					Port:       p.Port,
					Service:    p.Service,
					BadgeClass: "bg-indigo-100 text-indigo-800 border-indigo-300 dark:bg-indigo-950/70 dark:text-indigo-300 dark:border-indigo-800",
				})
			}
		case 3000, 5000, 5173, 8000, 8888:
			if !seenCategories["dev"] {
				seenCategories["dev"] = true
				badges = append(badges, ServiceBadge{
					Label:      "⚡ Dev",
					Port:       p.Port,
					Service:    p.Service,
					BadgeClass: "bg-violet-100 text-violet-800 border-violet-300 dark:bg-violet-950/70 dark:text-violet-300 dark:border-violet-800",
				})
			}
		case 88, 389, 636, 3268, 1812, 1813:
			if !seenCategories["auth"] {
				seenCategories["auth"] = true
				badges = append(badges, ServiceBadge{
					Label:      "🪪 認証/AD",
					Port:       p.Port,
					Service:    p.Service,
					BadgeClass: "bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/70 dark:text-emerald-300 dark:border-emerald-800",
				})
			}
		case 445, 548:
			if !seenCategories["smb"] {
				seenCategories["smb"] = true
				badges = append(badges, ServiceBadge{
					Label:      "📁 ファイル共有",
					Port:       p.Port,
					Service:    p.Service,
					BadgeClass: "bg-teal-100 text-teal-800 border-teal-300 dark:bg-teal-950/70 dark:text-teal-300 dark:border-teal-800",
				})
			}
		case 631, 9100:
			if !seenCategories["printer"] {
				seenCategories["printer"] = true
				badges = append(badges, ServiceBadge{
					Label:      "🖨️ プリンタ",
					Port:       p.Port,
					Service:    p.Service,
					BadgeClass: "bg-cyan-100 text-cyan-800 border-cyan-300 dark:bg-cyan-950/70 dark:text-cyan-300 dark:border-cyan-800",
				})
			}
		case 3306, 5432, 6379, 27017, 9200, 1433, 1521:
			if !seenCategories["db"] {
				seenCategories["db"] = true
				badges = append(badges, ServiceBadge{
					Label:      "🗄️ DB",
					Port:       p.Port,
					Service:    p.Service,
					BadgeClass: "bg-slate-100 text-slate-800 border-slate-300 dark:bg-slate-800 dark:text-slate-200 dark:border-slate-700",
				})
			}
		case 53:
			if !seenCategories["dns"] {
				seenCategories["dns"] = true
				badges = append(badges, ServiceBadge{
					Label:      "📡 DNS",
					Port:       p.Port,
					Service:    "DNS",
					BadgeClass: "bg-slate-100 text-slate-800 border-slate-300 dark:bg-slate-800 dark:text-slate-200 dark:border-slate-700",
				})
			}
		case 554:
			if !seenCategories["camera"] {
				seenCategories["camera"] = true
				badges = append(badges, ServiceBadge{
					Label:      "📹 RTSP",
					Port:       p.Port,
					Service:    "RTSP",
					BadgeClass: "bg-purple-100 text-purple-800 border-purple-300 dark:bg-purple-950/70 dark:text-purple-300 dark:border-purple-800",
				})
			}
		case 8008:
			if !seenCategories["cast"] {
				seenCategories["cast"] = true
				badges = append(badges, ServiceBadge{
					Label:      "📺 Cast",
					Port:       p.Port,
					Service:    "Google Cast",
					BadgeClass: "bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/70 dark:text-amber-300 dark:border-amber-800",
				})
			}
		}
	}
	return badges
}

// HasServiceInfo returns true if host has any recognized service info badges
func (h *Host) HasServiceInfo() bool {
	return len(h.ServiceInfoBadges()) > 0
}

// IPID returns sanitized IP string for HTML element IDs (e.g. "192-168-1-1" or "192-168-1-1-101")
func (h *Host) IPID() string {
	cleanIP := strings.ReplaceAll(strings.ReplaceAll(h.IP, ".", "-"), ":", "-")
	if h.ID > 0 {
		return fmt.Sprintf("%s-%d", cleanIP, h.ID)
	}
	return cleanIP
}

// IsNewHost returns true if host was first seen within the last 24 hours and is not yet approved
func (h *Host) IsNewHost() bool {
	if h.IsApproved {
		return false
	}
	return time.Since(h.FirstSeen) < 24*time.Hour
}

// HasPingRTT returns true if Ping RTT measurement exists
func (h *Host) HasPingRTT() bool {
	return h.PingRTTMs != nil && *h.PingRTTMs >= 0
}

// PingRTTFormatted returns formatted RTT string (e.g. "2.3 ms")
func (h *Host) PingRTTFormatted() string {
	if h.PingRTTMs == nil {
		return "-"
	}
	return fmt.Sprintf("%.1f ms", *h.PingRTTMs)
}

// JitterFormatted returns formatted Jitter string (e.g. "±0.5 ms")
func (h *Host) JitterFormatted() string {
	if h.PingJitterMs == nil || *h.PingJitterMs < 0 {
		return "安定"
	}
	return fmt.Sprintf("±%.1f ms", *h.PingJitterMs)
}

// PingRTTLevel returns quality level for CSS badge styling
func (h *Host) PingRTTLevel() string {
	if h.PingRTTMs == nil {
		return "none"
	}
	if *h.PingRTTMs < 15.0 {
		return "fast"
	} else if *h.PingRTTMs < 60.0 {
		return "normal"
	}
	return "slow"
}

var (
	portSeverityResolverMu sync.RWMutex
	portSeverityResolver   func(port int) string
)

// SetPortSeverityResolver sets a dynamic resolver function for open port severity
func SetPortSeverityResolver(fn func(port int) string) {
	portSeverityResolverMu.Lock()
	defer portSeverityResolverMu.Unlock()
	portSeverityResolver = fn
}

// resolvePortSeverity determines severity for a given port number
func resolvePortSeverity(port int) (severity, icon, badgeClass, dotClass string) {
	portSeverityResolverMu.RLock()
	fn := portSeverityResolver
	portSeverityResolverMu.RUnlock()

	sev := ""
	if fn != nil {
		sev = fn(port)
	}

	if sev == "" {
		switch port {
		case 1194, 1723, 5555, 5938, 7070:
			sev = "danger"
		case 23, 3389, 5900:
			sev = "warning"
		default:
			sev = "info"
		}
	}

	switch sev {
	case "danger":
		return "danger", "🚨", "bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 border border-rose-300 dark:border-rose-800 font-bold", "bg-rose-500"
	case "warning":
		return "warning", "⚠️", "bg-amber-50 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800 font-semibold", "bg-amber-500"
	default:
		if port == 22 {
			return "info", "ℹ️", "bg-sky-50 dark:bg-sky-950/60 text-sky-800 dark:text-sky-300 border border-sky-300 dark:border-sky-800 font-medium", "bg-sky-500"
		}
		return "info", "ℹ️", "bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800/60 font-medium", "bg-emerald-500"
	}
}

// OpenPortsList parses comma-separated "port:service" string into slice of PortInfo
func (h *Host) OpenPortsList() []PortInfo {
	if strings.TrimSpace(h.OpenPorts) == "" {
		return nil
	}
	var list []PortInfo
	parts := strings.Split(h.OpenPorts, ",")
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), ":", 2)
		if len(kv) >= 1 {
			portNum, err := strconv.Atoi(kv[0])
			if err == nil {
				svcName := "Unknown"
				if len(kv) == 2 {
					svcName = kv[1]
				}
				sev, icon, badgeClass, dotClass := resolvePortSeverity(portNum)
				list = append(list, PortInfo{
					Port:       portNum,
					Service:    svcName,
					Severity:   sev,
					Icon:       icon,
					BadgeClass: badgeClass,
					DotClass:   dotClass,
				})
			}
		}
	}
	return list
}

// HasOpenPorts returns true if any open ports were detected
func (h *Host) HasOpenPorts() bool {
	return len(h.OpenPortsList()) > 0
}

// HasTLS returns true if TLS info is available
func (h *Host) HasTLS() bool {
	return h.TLSSubject != "" || h.TLSExpiry != nil
}

// TLSExpiresSoon returns true if certificate expires within 30 days
func (h *Host) TLSExpiresSoon() bool {
	if h.TLSExpiry == nil {
		return false
	}
	return time.Until(*h.TLSExpiry) < 30*24*time.Hour
}

// DaysUntilTLSExpiry returns days remaining until certificate expiry
func (h *Host) DaysUntilTLSExpiry() int {
	if h.TLSExpiry == nil {
		return 0
	}
	days := int(time.Until(*h.TLSExpiry).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

// IsRandomizedMAC returns true if the MAC address has the Locally Administered Address (LAA) bit set
func (h *Host) IsRandomizedMAC() bool {
	mac := strings.ToLower(strings.TrimSpace(h.MACAddress))
	if len(mac) < 2 {
		return false
	}
	// Check second hex digit of first byte (2, 6, a, e indicate randomized/LAA MAC)
	secondChar := mac[1]
	return secondChar == '2' || secondChar == '6' || secondChar == 'a' || secondChar == 'e'
}

// ConnectionType returns "wifi", "ethernet", or "unknown"
func (h *Host) ConnectionType() string {
	combined := strings.ToLower(h.Hostname + " " + h.MDNSModel + " " + h.VendorModel + " " + h.UPnPName + " " + h.DisplayName)

	// 1. Definite mobile / wireless-only device classes
	if strings.Contains(combined, "iphone") ||
		strings.Contains(combined, "ipad") ||
		strings.Contains(combined, "watch") ||
		strings.Contains(combined, "galaxy") ||
		strings.Contains(combined, "pixel") ||
		strings.Contains(combined, "android") ||
		strings.Contains(combined, "google home") ||
		strings.Contains(combined, "nest") ||
		strings.Contains(combined, "echo") ||
		strings.Contains(combined, "homepod") ||
		strings.Contains(combined, "cast") ||
		strings.Contains(combined, "espressif") ||
		strings.Contains(combined, "tuya") ||
		strings.Contains(combined, "shelly") ||
		strings.Contains(combined, "switch") ||
		strings.Contains(combined, "airplay") {
		return "wifi"
	}

	// 2. Private / Randomized MAC is almost exclusively used on Wi-Fi interfaces
	if h.IsRandomizedMAC() {
		return "wifi"
	}

	// 3. Known wired infrastructure (Routers, Gateways, Managed Switches, NAS, Hypervisors, Network APs)
	if strings.Contains(combined, "openwrt") ||
		strings.Contains(combined, "luci") ||
		strings.Contains(combined, "synology") ||
		strings.Contains(combined, "qnap") ||
		strings.Contains(combined, "truenas") ||
		strings.Contains(combined, "proxmox") ||
		strings.Contains(combined, "esxi") ||
		strings.Contains(combined, "netgear") ||
		strings.Contains(combined, "cisco") ||
		strings.Contains(combined, "ubiquiti") ||
		strings.Contains(combined, "unifi") ||
		strings.Contains(combined, "yamaha") ||
		strings.Contains(combined, "fortinet") ||
		strings.Contains(combined, "mikrotik") ||
		strings.Contains(combined, "allied telesis") ||
		strings.Contains(combined, "juniper") ||
		strings.Contains(combined, "aruba") ||
		strings.Contains(combined, "router") ||
		strings.Contains(combined, "access point") ||
		strings.Contains(combined, "server") {
		return "ethernet"
	}

	// 4. Ping latency & jitter statistical signature
	if h.PingRTTMs != nil && *h.PingRTTMs >= 0 {
		if *h.PingRTTMs < 0.8 && (h.PingJitterMs == nil || *h.PingJitterMs < 0.2) {
			return "ethernet"
		}
		if *h.PingRTTMs >= 1.5 || (h.PingJitterMs != nil && *h.PingJitterMs >= 0.4) {
			return "wifi"
		}
	}

	return "unknown"
}

// ConnectionLabel returns user-friendly label (e.g. "📶 Wi-Fi", "🔌 有線LAN")
func (h *Host) ConnectionLabel() string {
	switch h.ConnectionType() {
	case "wifi":
		return "📶 Wi-Fi"
	case "ethernet":
		return "🔌 有線LAN"
	default:
		return "❓ 不明"
	}
}

// ConnectionBadgeClass returns Tailwind badge styling class
func (h *Host) ConnectionBadgeClass() string {
	switch h.ConnectionType() {
	case "wifi":
		return "bg-sky-50 text-sky-700 dark:bg-sky-950/60 dark:text-sky-300 border-sky-200 dark:border-sky-800/60"
	case "ethernet":
		return "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border-slate-200 dark:border-slate-700"
	default:
		return "bg-slate-50 text-slate-500 dark:bg-slate-900 dark:text-slate-400 border-slate-200 dark:border-slate-800"
	}
}

// ConnectionReason returns human-readable explanation of why this connection type was determined
func (h *Host) ConnectionReason() string {
	combined := strings.ToLower(h.Hostname + " " + h.MDNSModel + " " + h.VendorModel + " " + h.UPnPName + " " + h.DisplayName)
	if strings.Contains(combined, "iphone") || strings.Contains(combined, "ipad") || strings.Contains(combined, "watch") || strings.Contains(combined, "galaxy") {
		return "モバイル機器"
	}
	if strings.Contains(combined, "google home") || strings.Contains(combined, "cast") || strings.Contains(combined, "espressif") {
		return "スマート家電/IoT"
	}
	if h.IsRandomizedMAC() {
		return "ランダムMAC"
	}
	if strings.Contains(combined, "netgear") || strings.Contains(combined, "cisco") || strings.Contains(combined, "yamaha") || strings.Contains(combined, "ubiquiti") || strings.Contains(combined, "router") || strings.Contains(combined, "access point") {
		return "ネットワーク機器 (AP/ルーター)"
	}
	if strings.Contains(combined, "openwrt") || strings.Contains(combined, "synology") || strings.Contains(combined, "server") {
		return "固定インフラ"
	}
	if h.PingRTTMs != nil && *h.PingRTTMs < 0.8 {
		return "超低遅延 (<0.8ms)"
	}
	if h.PingRTTMs != nil && *h.PingRTTMs >= 1.5 {
		return "遅延/ジッター特性"
	}
	return "推定"
}

// SearchKeywords returns a consolidated lowercase string of all searchable attributes of the host
func (h *Host) SearchKeywords() string {
	var parts []string
	parts = append(parts, h.IP, h.Hostname, h.DisplayName, h.MACAddress, h.VendorModel, h.OSVendor, h.MDNSModel, h.HTTPTitle, h.UPnPName, h.UPnPModel, h.OpenPorts, h.Status, h.ConnectionLabel(), h.ConnectionReason())
	if h.IsApproved {
		parts = append(parts, "承認", "承認済", "approved")
	} else {
		parts = append(parts, "未承認", "unapproved", "警告")
	}
	if h.IsStaticIP {
		parts = append(parts, "固定ip", "static")
	}
	if h.IsStorming {
		parts = append(parts, "ストーム", "異常通信", "storm")
	}
	return strings.ToLower(strings.Join(parts, " "))
}

// UpsertHostOnScan inserts a newly scanned host or updates an existing host.
// If an existing host with the same MAC address is found, it updates that host's IP and status.
// If a new host with a different MAC address arrives on an existing IP, the previous host is kept as status='down',
// and the new host is inserted with status='up'.
func (db *DB) UpsertHostOnScan(h *Host) (isNew bool, isReplaced bool, err error) {
	now := time.Now()
	normMAC := strings.ToLower(strings.TrimSpace(h.MACAddress))

	var existing *Host
	if normMAC != "" {
		existing, err = db.GetHostByMAC(normMAC)
		if err != nil {
			return false, false, err
		}
	} else {
		// If MAC is not available (e.g. VPN or manual), fallback to IP match
		existing, err = db.GetHost(h.IP)
		if err != nil {
			return false, false, err
		}
	}

	if existing == nil {
		// This MAC (or MAC-less host) is new.
		// Check if another host was previously using this IP.
		prevHostOnIP, err := db.GetHost(h.IP)
		if err != nil {
			return false, false, err
		}

		if prevHostOnIP != nil {
			// Mark the previous host on this IP as 'down' so it remains visible as offline history
			isReplaced = true
			_, _ = db.Exec("UPDATE hosts SET status = 'down' WHERE id = ?", prevHostOnIP.ID)
		}

		initialIPv6 := h.IPv6Addresses
		if isIPv6(h.IP) {
			initialIPv6 = mergeIPv6Addresses(initialIPv6, h.IP)
		}

		query := `
		INSERT INTO hosts (
			ip, segment_id, mac_address, hostname, vendor_model, display_name,
			os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
			open_ports, http_title, upnp_name, upnp_model, upnp_serial,
			tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
			is_approved, is_protected, is_static_ip, is_dhcp,
			is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
			first_seen, last_seen, ipv6_addresses
		) VALUES (
			?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, 100.0,
			?, ?, ?, ?, ?,
			?, ?, ?, 0, 0,
			?, 0, 0, ?,
			0, 0, 0, '', NULL,
			?, ?, ?
		)
		`
		status := h.Status
		if status == "" {
			status = "up"
		}
		_, err = db.Exec(query,
			h.IP, h.SegmentID, normMAC, h.Hostname, h.VendorModel, h.DisplayName,
			h.OSVendor, status, h.PingRTTMs, h.PingJitterMs,
			h.OpenPorts, h.HTTPTitle, h.UPnPName, h.UPnPModel, h.UPnPSerial,
			h.TLSSubject, h.TLSExpiry, h.MDNSModel,
			h.IsApproved, h.IsDHCP, now, now, initialIPv6,
		)
		return true, isReplaced, err
	}

	existingIsV4 := isIPv4(existing.IP)
	incomingIsV4 := isIPv4(h.IP)

	targetIP := existing.IP
	var mergedIPv6 string

	if incomingIsV4 {
		targetIP = h.IP
		mergedIPv6 = mergeIPv6Addresses(existing.IPv6Addresses, h.IPv6Addresses)
		if !existingIsV4 && existing.IP != "" {
			mergedIPv6 = mergeIPv6Addresses(mergedIPv6, existing.IP)
		}
	} else {
		// Incoming is IPv6
		if existingIsV4 {
			// Existing has IPv4, keep existing IPv4 as primary IP
			targetIP = existing.IP
			mergedIPv6 = mergeIPv6Addresses(existing.IPv6Addresses, h.IP, h.IPv6Addresses)
		} else {
			// Both or existing is IPv6
			if h.IP != "" {
				targetIP = h.IP
			}
			mergedIPv6 = mergeIPv6Addresses(existing.IPv6Addresses, h.IP, h.IPv6Addresses)
		}
	}

	// Host with this MAC (or IP fallback) exists.
	// Check if this host is moving to a new IPv4 where another host previously was.
	if incomingIsV4 && existingIsV4 && existing.IP != targetIP {
		prevHostOnTargetIP, _ := db.GetHost(targetIP)
		if prevHostOnTargetIP != nil && prevHostOnTargetIP.ID != existing.ID {
			// Mark that host on target IP as down
			isReplaced = true
			_, _ = db.Exec("UPDATE hosts SET status = 'down' WHERE id = ?", prevHostOnTargetIP.ID)
		}
	}

	isApproved := existing.IsApproved
	firstSeen := existing.FirstSeen
	if h.IsApproved {
		isApproved = true
	}

	hostname := existing.Hostname
	if h.Hostname != "" {
		hostname = h.Hostname
	}
	vendorModel := existing.VendorModel
	if h.VendorModel != "" {
		vendorModel = h.VendorModel
	}
	osVendor := existing.OSVendor
	if h.OSVendor != "" {
		osVendor = h.OSVendor
	}
	displayName := existing.DisplayName
	if displayName == "" && h.DisplayName != "" {
		displayName = h.DisplayName
	}

	mac := existing.MACAddress
	if normMAC != "" {
		mac = normMAC
	}

	pingRTT := h.PingRTTMs
	if pingRTT == nil {
		pingRTT = existing.PingRTTMs
	}

	jitter := h.PingJitterMs
	if jitter == nil {
		jitter = existing.PingJitterMs
	}

	openPorts := h.OpenPorts
	if openPorts == "" && existing.OpenPorts != "" {
		openPorts = existing.OpenPorts
	}
	httpTitle := h.HTTPTitle
	if httpTitle == "" && existing.HTTPTitle != "" {
		httpTitle = existing.HTTPTitle
	}
	upnpName := h.UPnPName
	if upnpName == "" && h.UPnPModel == "" {
		upnpName = existing.UPnPName
	}
	upnpModel := h.UPnPModel
	if upnpModel == "" {
		upnpModel = existing.UPnPModel
	}
	upnpSerial := h.UPnPSerial
	if upnpSerial == "" {
		upnpSerial = existing.UPnPSerial
	}
	tlsSubj := h.TLSSubject
	tlsExp := h.TLSExpiry
	if tlsSubj == "" && tlsExp == nil && existing.TLSSubject != "" {
		tlsSubj = existing.TLSSubject
		tlsExp = existing.TLSExpiry
	}
	mdnsModel := h.MDNSModel
	if mdnsModel == "" {
		mdnsModel = existing.MDNSModel
	}

	isDHCP := existing.IsDHCP || h.IsDHCP

	status := h.Status
	if status == "" {
		status = existing.Status
	}

	query := `
	UPDATE hosts SET
		ip = ?,
		segment_id = COALESCE(?, segment_id),
		mac_address = ?,
		hostname = ?,
		vendor_model = ?,
		display_name = ?,
		os_vendor = ?,
		status = ?,
		ping_rtt_ms = ?,
		ping_jitter_ms = ?,
		open_ports = ?,
		http_title = ?,
		upnp_name = ?,
		upnp_model = ?,
		upnp_serial = ?,
		tls_subject = ?,
		tls_expiry = ?,
		mdns_model = ?,
		is_approved = ?,
		is_dhcp = ?,
		first_seen = ?,
		last_seen = ?,
		ipv6_addresses = ?
	WHERE id = ?
	`
	_, err = db.Exec(query,
		targetIP, h.SegmentID, mac, hostname, vendorModel, displayName,
		osVendor, status, pingRTT, jitter, openPorts,
		httpTitle, upnpName, upnpModel, upnpSerial,
		tlsSubj, tlsExp, mdnsModel,
		isApproved, isDHCP, firstSeen, now, mergedIPv6, existing.ID,
	)
	return false, isReplaced, err
}

// GetHost fetches the active host by IP (preferring status='up', then latest last_seen)
func (db *DB) GetHost(ip string) (*Host, error) {
	query := `
	SELECT
		id, ip, segment_id, mac_address, hostname, vendor_model, display_name,
		os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
		open_ports, http_title, upnp_name, upnp_model, upnp_serial,
		tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
		is_approved, is_protected, is_static_ip, is_dhcp,
		is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
		first_seen, last_seen, last_port_scan, next_port_scan, ignored_ports, agent_id, ipv6_addresses
	FROM hosts
	WHERE ip = ?
	ORDER BY CASE WHEN status = 'up' THEN 0 ELSE 1 END, last_seen DESC
	LIMIT 1
	`
	row := db.QueryRow(query, ip)
	h, err := scanHost(row)
	if err == nil && h != nil {
		return h, nil
	}

	clean := strings.ToLower(strings.TrimSpace(ip))
	if idx := strings.Index(clean, "%"); idx != -1 {
		clean = clean[:idx]
	}
	parsed := net.ParseIP(clean)
	if parsed != nil && parsed.To4() == nil {
		v6Query := `
		SELECT
			id, ip, segment_id, mac_address, hostname, vendor_model, display_name,
			os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
			open_ports, http_title, upnp_name, upnp_model, upnp_serial,
			tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
			is_approved, is_protected, is_static_ip, is_dhcp,
			is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
			first_seen, last_seen, last_port_scan, next_port_scan, ignored_ports, agent_id, ipv6_addresses
		FROM hosts
		WHERE instr(LOWER(ipv6_addresses), ?) > 0
		ORDER BY CASE WHEN status = 'up' THEN 0 ELSE 1 END, last_seen DESC
		LIMIT 1
		`
		row = db.QueryRow(v6Query, parsed.String())
		return scanHost(row)
	}

	return h, err
}

// GetHostByIP fetches a host by IP address (alias for GetHost)
func (db *DB) GetHostByIP(ip string) (*Host, error) {
	return db.GetHost(ip)
}

// GetHostByID fetches a host by internal primary key ID
func (db *DB) GetHostByID(id int64) (*Host, error) {
	query := `
	SELECT
		id, ip, segment_id, mac_address, hostname, vendor_model, display_name,
		os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
		open_ports, http_title, upnp_name, upnp_model, upnp_serial,
		tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
		is_approved, is_protected, is_static_ip, is_dhcp,
		is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
		first_seen, last_seen, last_port_scan, next_port_scan, ignored_ports, agent_id, ipv6_addresses
	FROM hosts
	WHERE id = ?
	`
	row := db.QueryRow(query, id)
	return scanHost(row)
}

// GetHostByMAC fetches a host by normalized MAC address (preferring status='up', then latest last_seen)
func (db *DB) GetHostByMAC(mac string) (*Host, error) {
	norm := strings.ToLower(strings.TrimSpace(mac))
	if norm == "" {
		return nil, nil
	}
	query := `
	SELECT
		id, ip, segment_id, mac_address, hostname, vendor_model, display_name,
		os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
		open_ports, http_title, upnp_name, upnp_model, upnp_serial,
		tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
		is_approved, is_protected, is_static_ip, is_dhcp,
		is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
		first_seen, last_seen, last_port_scan, next_port_scan, ignored_ports, agent_id, ipv6_addresses
	FROM hosts
	WHERE LOWER(TRIM(mac_address)) = ?
	ORDER BY CASE WHEN status = 'up' THEN 0 ELSE 1 END, last_seen DESC
	LIMIT 1
	`
	row := db.QueryRow(query, norm)
	return scanHost(row)
}

// ListHosts lists hosts, optionally filtered by segment and online status (defaults to 3-day history)
func (db *DB) ListHosts(segmentID *int64, onlineOnly bool) ([]*Host, error) {
	if onlineOnly {
		return db.ListHostsFiltered(segmentID, "online", 0)
	}
	return db.ListHostsFiltered(segmentID, "days", 3)
}

// ListHostsFiltered lists hosts with flexible filterMode ("online", "days", "all")
func (db *DB) ListHostsFiltered(segmentID *int64, filterMode string, daysLimit int) ([]*Host, error) {
	return db.ListHostsFilteredWithAgent(segmentID, filterMode, daysLimit, nil)
}

// ListHostsFilteredWithAgent lists hosts with agent scope:
// - agentID == nil or *agentID == "": server local hosts only (agent_id IS NULL)
// - agentID != nil && *agentID == "*": all hosts across all sites and server
// - agentID != nil && *agentID != "": remote hosts for specified agent UUID
func (db *DB) ListHostsFilteredWithAgent(segmentID *int64, filterMode string, daysLimit int, agentID *string) ([]*Host, error) {
	var query strings.Builder
	var args []interface{}

	query.WriteString(`
	SELECT
		id, ip, segment_id, mac_address, hostname, vendor_model, display_name,
		os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
		open_ports, http_title, upnp_name, upnp_model, upnp_serial,
		tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
		is_approved, is_protected, is_static_ip, is_dhcp,
		is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
		first_seen, last_seen, last_port_scan, next_port_scan, ignored_ports, agent_id, ipv6_addresses
	FROM hosts
	WHERE 1=1
	`)

	if agentID == nil || *agentID == "" {
		query.WriteString(" AND agent_id IS NULL")
	} else if *agentID != "*" {
		query.WriteString(" AND agent_id = ?")
		args = append(args, *agentID)
	}

	if segmentID != nil {
		query.WriteString(" AND segment_id = ?")
		args = append(args, *segmentID)
	}

	switch filterMode {
	case "online":
		query.WriteString(" AND status = 'up'")
	case "days":
		if daysLimit <= 0 {
			daysLimit = 3
		}
		query.WriteString(" AND (status = 'up' OR (status != 'up' AND ((last_seen IS NOT NULL AND last_seen >= datetime('now', '-' || ? || ' days')) OR (last_seen IS NULL AND first_seen >= datetime('now', '-' || ? || ' days')))))")
		args = append(args, daysLimit, daysLimit)
	case "all":
		// no filter
	default:
		// Default to 3 days
		query.WriteString(" AND (status = 'up' OR (status != 'up' AND ((last_seen IS NOT NULL AND last_seen >= datetime('now', '-3 days')) OR (last_seen IS NULL AND first_seen >= datetime('now', '-3 days')))))")
	}

	query.WriteString(" ORDER BY is_storming DESC, is_approved ASC, ip ASC, CASE WHEN status = 'up' THEN 0 ELSE 1 END, last_seen DESC")

	rows, err := db.Query(query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []*Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}

	// Resolve agent names if any remote hosts are present
	agents, err := db.ListAgents()
	if err == nil && len(agents) > 0 {
		agentNameMap := make(map[string]string)
		for _, a := range agents {
			agentNameMap[a.ID] = a.Name
		}
		for _, h := range hosts {
			if h.AgentID != nil {
				h.AgentName = agentNameMap[*h.AgentID]
			}
		}
	}

	// Mark superseded hosts (offline hosts where an active host exists on the same IP and same agent_id)
	onlineKeys := make(map[string]bool)
	for _, h := range hosts {
		if h.Status == "up" {
			key := h.IP
			if h.AgentID != nil {
				key = *h.AgentID + ":" + h.IP
			}
			onlineKeys[key] = true
		}
	}
	for _, h := range hosts {
		key := h.IP
		if h.AgentID != nil {
			key = *h.AgentID + ":" + h.IP
		}
		if h.Status != "up" && onlineKeys[key] {
			h.IsPreviousHost = true
		}
	}

	db.enrichHostsWithPingHistory(hosts)

	return hosts, rows.Err()
}

func (db *DB) enrichHostsWithPingHistory(hosts []*Host) {
	if len(hosts) == 0 {
		return
	}
	historyMap, err := db.GetBatchPingHistory7d()
	if err != nil {
		return
	}

	for _, h := range hosts {
		items := historyMap[h.IP]
		h.PingChartSVG = RenderSparklineSVG(items, 280, 36)
		h.UptimeBlocksSVG = RenderUptimeBlocksSVG(items, 35)
		h.PingStats7d, _ = ComputePingStats7d(items)
	}
}

// UpdateHostStatus updates the host status and last_seen if up
func (db *DB) UpdateHostStatus(ip string, status string) error {
	now := time.Now()
	var query string
	if status == "up" {
		query = "UPDATE hosts SET status = ?, last_seen = ? WHERE ip = ?"
		_, err := db.Exec(query, status, now, ip)
		return err
	}
	query = "UPDATE hosts SET status = ? WHERE ip = ?"
	_, err := db.Exec(query, status, ip)
	return err
}

// UpdateHostBroadcastStats updates broadcast traffic stats and storm status
func (db *DB) UpdateHostBroadcastStats(ip string, count1m int, isStorming bool) error {
	query := "UPDATE hosts SET broadcast_count_1m = ?, is_storming = ? WHERE ip = ?"
	_, err := db.Exec(query, count1m, isStorming, ip)
	return err
}

// UpdateHostKumaStatus updates Uptime Kuma monitoring link and status
func (db *DB) UpdateHostKumaStatus(ip string, kumaID *int64, isMonitored, isPaused, hasConflict bool, kumaName string) error {
	query := `
	UPDATE hosts SET
		uptime_kuma_id = ?,
		is_monitored = ?,
		is_paused = ?,
		has_conflict = ?,
		kuma_name = ?
	WHERE ip = ?
	`
	_, err := db.Exec(query, kumaID, isMonitored, isPaused, hasConflict, kumaName, ip)
	return err
}

// ToggleApprovalByID toggles the approval status of a host by its internal ID
func (db *DB) ToggleApprovalByID(id int64) (bool, error) {
	var current bool
	err := db.QueryRow("SELECT is_approved FROM hosts WHERE id = ?", id).Scan(&current)
	if err != nil {
		return false, err
	}

	newVal := !current
	_, err = db.Exec("UPDATE hosts SET is_approved = ? WHERE id = ?", newVal, id)
	return newVal, err
}

// ToggleApproval toggles the approval status of a host (fallback using IP)
func (db *DB) ToggleApproval(ip string) (bool, error) {
	h, err := db.GetHost(ip)
	if err != nil || h == nil {
		return false, fmt.Errorf("host not found: %s", ip)
	}
	return db.ToggleApprovalByID(h.ID)
}

// ToggleProtectionByID toggles the protection flag of a host by its internal ID
func (db *DB) ToggleProtectionByID(id int64) (bool, error) {
	var current bool
	err := db.QueryRow("SELECT is_protected FROM hosts WHERE id = ?", id).Scan(&current)
	if err != nil {
		return false, err
	}

	newVal := !current
	_, err = db.Exec("UPDATE hosts SET is_protected = ? WHERE id = ?", newVal, id)
	return newVal, err
}

// ToggleProtection toggles the protection flag of a host (fallback using IP)
func (db *DB) ToggleProtection(ip string) (bool, error) {
	h, err := db.GetHost(ip)
	if err != nil || h == nil {
		return false, fmt.Errorf("host not found: %s", ip)
	}
	return db.ToggleProtectionByID(h.ID)
}

// ToggleDHCPByID toggles the is_dhcp flag of a host by its internal ID
func (db *DB) ToggleDHCPByID(id int64) (bool, error) {
	var current bool
	err := db.QueryRow("SELECT is_dhcp FROM hosts WHERE id = ?", id).Scan(&current)
	if err != nil {
		return false, err
	}

	newVal := !current
	_, err = db.Exec("UPDATE hosts SET is_dhcp = ? WHERE id = ?", newVal, id)
	return newVal, err
}

// ToggleDHCP toggles the is_dhcp flag of a host (fallback using IP)
func (db *DB) ToggleDHCP(ip string) (bool, error) {
	h, err := db.GetHost(ip)
	if err != nil || h == nil {
		return false, fmt.Errorf("host not found: %s", ip)
	}
	return db.ToggleDHCPByID(h.ID)
}

// UpdateHostManualByID updates manually editable fields by host ID
func (db *DB) UpdateHostManualByID(id int64, displayName, vendorModel string, isStaticIP bool, ignoredPorts string) error {
	query := `
	UPDATE hosts SET
		display_name = ?,
		vendor_model = CASE WHEN ? != '' THEN ? ELSE vendor_model END,
		is_static_ip = ?,
		ignored_ports = ?
	WHERE id = ?
	`
	_, err := db.Exec(query, displayName, vendorModel, vendorModel, isStaticIP, ignoredPorts, id)
	return err
}

// UpdateHostManual updates manually editable fields (fallback using IP)
func (db *DB) UpdateHostManual(ip, displayName, vendorModel string, isStaticIP bool, ignoredPorts string) error {
	h, err := db.GetHost(ip)
	if err != nil || h == nil {
		return fmt.Errorf("host not found: %s", ip)
	}
	return db.UpdateHostManualByID(h.ID, displayName, vendorModel, isStaticIP, ignoredPorts)
}

// TogglePortIgnoredByID toggles whether warnings for a specific port are suppressed on a host by ID
func (db *DB) TogglePortIgnoredByID(id int64, port int) error {
	h, err := db.GetHostByID(id)
	if err != nil || h == nil {
		return fmt.Errorf("host not found with id: %d", id)
	}
	newIgnored := togglePortInList(h.IgnoredPorts, port)
	_, err = db.Exec("UPDATE hosts SET ignored_ports = ? WHERE id = ?", newIgnored, id)
	return err
}

// TogglePortIgnored toggles whether warnings for a specific port are suppressed on a host
func (db *DB) TogglePortIgnored(ip string, port int) error {
	h, err := db.GetHost(ip)
	if err != nil || h == nil {
		return fmt.Errorf("host not found: %s", ip)
	}
	return db.TogglePortIgnoredByID(h.ID, port)
}

func togglePortInList(ignored string, port int) string {
	parts := strings.Split(ignored, ",")
	var list []int
	found := false
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		val, err := strconv.Atoi(p)
		if err != nil {
			continue
		}
		if val == port {
			found = true
		} else {
			list = append(list, val)
		}
	}
	if !found {
		list = append(list, port)
	}
	sort.Ints(list)
	var strList []string
	for _, val := range list {
		strList = append(strList, strconv.Itoa(val))
	}
	return strings.Join(strList, ",")
}

// CreateManualHost creates a manually defined host
func (db *DB) CreateManualHost(h *Host) error {
	now := time.Now()
	normMAC := strings.ToLower(strings.TrimSpace(h.MACAddress))
	initialIPv6 := h.IPv6Addresses
	if isIPv6(h.IP) {
		initialIPv6 = mergeIPv6Addresses(initialIPv6, h.IP)
	}
	query := `
	INSERT INTO hosts (
		ip, segment_id, mac_address, hostname, vendor_model, display_name,
		os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
		open_ports, http_title, upnp_name, upnp_model, upnp_serial,
		tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
		is_approved, is_protected, is_static_ip, is_dhcp,
		is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
		first_seen, last_seen, ignored_ports, ipv6_addresses
	) VALUES (
		?, ?, ?, ?, ?, ?,
		?, ?, ?, ?, 100.0,
		?, ?, ?, ?, ?,
		?, ?, ?, ?, ?,
		?, ?, ?, ?,
		?, ?, ?, ?, ?,
		?, ?, ?, ?
	)
	`
	_, err := db.Exec(query,
		h.IP, h.SegmentID, normMAC, h.Hostname, h.VendorModel, h.DisplayName,
		h.OSVendor, h.Status, h.PingRTTMs, h.PingJitterMs,
		h.OpenPorts, h.HTTPTitle, h.UPnPName, h.UPnPModel, h.UPnPSerial,
		h.TLSSubject, h.TLSExpiry, h.MDNSModel, h.BroadcastCount1m, h.IsStorming,
		h.IsApproved, h.IsProtected, h.IsStaticIP, h.IsDHCP,
		h.IsMonitored, h.IsPaused, h.HasConflict, h.KumaName, h.UptimeKumaID,
		now, now, h.IgnoredPorts, initialIPv6,
	)
	return err
}

// DeleteHostByID deletes a host by internal ID
func (db *DB) DeleteHostByID(id int64) error {
	_, err := db.Exec("DELETE FROM hosts WHERE id = ?", id)
	return err
}

// DeleteHost deletes a host by IP (or all hosts on that IP if multiple)
func (db *DB) DeleteHost(ip string) error {
	_, err := db.Exec("DELETE FROM hosts WHERE ip = ?", ip)
	return err
}

type scannable interface {
	Scan(dest ...interface{}) error
}

func scanHost(s scannable) (*Host, error) {
	var h Host
	var segID sql.NullInt64
	var mac, host, vendor, disp, osVend, kumaName, openPorts sql.NullString
	var httpTitle, upnpName, upnpModel, upnpSerial, tlsSubj, mdnsModel sql.NullString
	var kumaID sql.NullInt64
	var lastSeen, tlsExp, lastPortScan, nextPortScan sql.NullTime
	var rtt, jitter, uptime sql.NullFloat64
	var ignoredPorts sql.NullString
	var agentID sql.NullString
	var ipv6Addrs sql.NullString

	err := s.Scan(
		&h.ID,
		&h.IP,
		&segID,
		&mac,
		&host,
		&vendor,
		&disp,
		&osVend,
		&h.Status,
		&rtt,
		&jitter,
		&uptime,
		&openPorts,
		&httpTitle,
		&upnpName,
		&upnpModel,
		&upnpSerial,
		&tlsSubj,
		&tlsExp,
		&mdnsModel,
		&h.BroadcastCount1m,
		&h.IsStorming,
		&h.IsApproved,
		&h.IsProtected,
		&h.IsStaticIP,
		&h.IsDHCP,
		&h.IsMonitored,
		&h.IsPaused,
		&h.HasConflict,
		&kumaName,
		&kumaID,
		&h.FirstSeen,
		&lastSeen,
		&lastPortScan,
		&nextPortScan,
		&ignoredPorts,
		&agentID,
		&ipv6Addrs,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if agentID.Valid && agentID.String != "" {
		h.AgentID = &agentID.String
	}

	if segID.Valid {
		h.SegmentID = &segID.Int64
	}
	h.MACAddress = mac.String
	h.Hostname = host.String
	h.VendorModel = vendor.String
	h.DisplayName = disp.String
	h.OSVendor = osVend.String
	h.KumaName = kumaName.String
	h.OpenPorts = openPorts.String
	h.HTTPTitle = httpTitle.String
	h.UPnPName = upnpName.String
	h.UPnPModel = upnpModel.String
	h.UPnPSerial = upnpSerial.String
	h.TLSSubject = tlsSubj.String
	h.MDNSModel = mdnsModel.String
	h.IgnoredPorts = ignoredPorts.String
	h.IPv6Addresses = ipv6Addrs.String

	if rtt.Valid {
		h.PingRTTMs = &rtt.Float64
	}
	if jitter.Valid {
		h.PingJitterMs = &jitter.Float64
	}
	if uptime.Valid {
		h.UptimePct = uptime.Float64
	} else {
		h.UptimePct = 100.0
	}

	if tlsExp.Valid {
		h.TLSExpiry = &tlsExp.Time
	}
	if kumaID.Valid {
		h.UptimeKumaID = &kumaID.Int64
	}
	if lastSeen.Valid {
		h.LastSeen = &lastSeen.Time
	}
	if lastPortScan.Valid {
		h.LastPortScan = &lastPortScan.Time
	}
	if nextPortScan.Valid {
		h.NextPortScan = &nextPortScan.Time
	}

	return &h, nil
}

// GetDuePortScanHost returns an online host that is due for its daily port scan (next_port_scan IS NULL OR next_port_scan <= now)
// Returns at most 1 host so that background scanning is performed sequentially without traffic spikes.
func (db *DB) GetDuePortScanHost() (*Host, error) {
	query := `
	SELECT
		id, ip, segment_id, mac_address, hostname, vendor_model, display_name,
		os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
		open_ports, http_title, upnp_name, upnp_model, upnp_serial,
		tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
		is_approved, is_protected, is_static_ip, is_dhcp,
		is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
		first_seen, last_seen, last_port_scan, next_port_scan, ignored_ports, agent_id, ipv6_addresses
	FROM hosts
	WHERE status = 'up' AND is_paused = 0 AND agent_id IS NULL AND (next_port_scan IS NULL OR next_port_scan <= ?)
	ORDER BY (CASE WHEN next_port_scan IS NULL THEN 0 ELSE 1 END), next_port_scan ASC
	LIMIT 1
	`
	row := db.QueryRow(query, time.Now())
	return scanHost(row)
}

// UpdateHostPortScanSchedule updates a host's scan result and schedules the next daily port scan
// with a random jitter (e.g. 20 to 28 hours from now) to prevent periodic beacon detection by UTMs/IDS.
func (db *DB) UpdateHostPortScanSchedule(ip string, openPorts string, nextScan time.Time) error {
	now := time.Now()
	query := `
	UPDATE hosts
	SET open_ports = ?,
	    last_port_scan = ?,
	    next_port_scan = ?
	WHERE ip = ?
	`
	_, err := db.Exec(query, openPorts, now, nextScan, ip)
	return err
}

// CalculateNextPortScanWithJitter computes next daily scan time: base + 24h + random jitter (-4h to +4h)
// Resulting interval is between 20h (72,000s) and 28h (100,800s).
func CalculateNextPortScanWithJitter(base time.Time) time.Time {
	jitterSeconds := 72000 + rand.Intn(28801) // 72000s (20h) to 100800s (28h)
	return base.Add(time.Duration(jitterSeconds) * time.Second)
}

// dhcpRangeItem represents a single parsed range chunk (e.g. "100-200", "192.168.0.100-200", or "192.168.0.100-192.168.0.200")
type dhcpRangeItem struct {
	raw         string
	isFullIP    bool
	startIP     net.IP
	endIP       net.IP
	startVal    uint32
	endVal      uint32
	isOctetOnly bool
	startOctet  int
	endOctet    int
}

func parseDHCPRangeItem(p string) (*dhcpRangeItem, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return nil, nil
	}

	delimiter := ""
	if strings.Contains(p, "-") {
		delimiter = "-"
	} else if strings.Contains(p, "~") {
		delimiter = "~"
	} else if strings.Contains(p, "〜") {
		delimiter = "〜"
	} else {
		return nil, fmt.Errorf("DHCPレンジ「%s」に範囲の区切り記号 (- または ~) が含まれていません (例: 100-200, 192.168.0.100-200)", p)
	}

	rangeParts := strings.SplitN(p, delimiter, 2)
	if len(rangeParts) != 2 {
		return nil, fmt.Errorf("DHCPレンジ「%s」の形式が不正です", p)
	}
	startStr := strings.TrimSpace(rangeParts[0])
	endStr := strings.TrimSpace(rangeParts[1])

	if startStr == "" || endStr == "" {
		return nil, fmt.Errorf("DHCPレンジ「%s」の開始値または終了値が空です", p)
	}

	startIP := net.ParseIP(startStr).To4()
	endIP := net.ParseIP(endStr).To4()

	// Case 1: Start is Full IP (e.g. 192.168.0.100)
	if startIP != nil {
		if endIP != nil {
			// Both are full IP: e.g. "192.168.0.100-192.168.0.200"
			startVal := ipToUint32(startIP)
			endVal := ipToUint32(endIP)
			if startVal > endVal {
				return nil, fmt.Errorf("DHCPレンジ「%s」: 開始IP (%s) は終了IP (%s) 以下である必要があります", p, startStr, endStr)
			}
			return &dhcpRangeItem{
				raw:      p,
				isFullIP: true,
				startIP:  startIP,
				endIP:    endIP,
				startVal: startVal,
				endVal:   endVal,
			}, nil
		}

		// End is not a full IP: check if it's a host octet number (e.g. "192.168.0.100-200")
		endNum, err := strconv.Atoi(endStr)
		if err != nil || endNum < 1 || endNum > 254 {
			return nil, fmt.Errorf("DHCPレンジ「%s」: 終了値「%s」が不正です。有効なIPアドレス (例: %d.%d.%d.200) またはホスト番号 (1〜254) を指定してください", p, endStr, startIP[0], startIP[1], startIP[2])
		}

		completedEndIP := net.IPv4(startIP[0], startIP[1], startIP[2], byte(endNum)).To4()
		startVal := ipToUint32(startIP)
		endVal := ipToUint32(completedEndIP)
		if startVal > endVal {
			return nil, fmt.Errorf("DHCPレンジ「%s」: 開始ホスト番号 (%d) は終了ホスト番号 (%d) 以下である必要があります", p, startIP[3], endNum)
		}

		return &dhcpRangeItem{
			raw:      p,
			isFullIP: true,
			startIP:  startIP,
			endIP:    completedEndIP,
			startVal: startVal,
			endVal:   endVal,
		}, nil
	}

	// Case 2: Start is NOT a full IP
	startNum, err1 := strconv.Atoi(startStr)
	if err1 != nil {
		return nil, fmt.Errorf("DHCPレンジ「%s」: 開始値「%s」が不正です。有効なIPアドレス (例: 192.168.0.100) またはホスト番号 (1〜254) を指定してください", p, startStr)
	}

	// If start is octet and end is full IP: reject with friendly guidance
	if endIP != nil {
		return nil, fmt.Errorf("DHCPレンジ「%s」: 開始「%s」がホスト番号ですが終了「%s」がフルIPです。両方ホスト番号 (例: %d-%d) または両方IP (例: %d.%d.%d.%d-%s) で指定してください", p, startStr, endStr, startNum, endIP[3], endIP[0], endIP[1], endIP[2], startNum, endStr)
	}

	// Both are octets: e.g. "100-200"
	endNum, err2 := strconv.Atoi(endStr)
	if err2 != nil {
		return nil, fmt.Errorf("DHCPレンジ「%s」: 終了値「%s」が不正です。ホスト番号 (1〜254) を指定してください", p, endStr)
	}

	if startNum < 1 || startNum > 254 {
		return nil, fmt.Errorf("DHCPレンジ「%s」: 開始ホスト番号 (%d) は 1〜254 の範囲で指定してください", p, startNum)
	}
	if endNum < 1 || endNum > 254 {
		return nil, fmt.Errorf("DHCPレンジ「%s」: 終了ホスト番号 (%d) は 1〜254 の範囲で指定してください", p, endNum)
	}
	if startNum > endNum {
		return nil, fmt.Errorf("DHCPレンジ「%s」: 開始ホスト番号 (%d) は終了ホスト番号 (%d) 以下である必要があります", p, startNum, endNum)
	}

	return &dhcpRangeItem{
		raw:         p,
		isOctetOnly: true,
		startOctet:  startNum,
		endOctet:    endNum,
	}, nil
}

func splitDHCPRangeParts(dhcpRange string) []string {
	parts := strings.FieldsFunc(dhcpRange, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';'
	})
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func calcSubnetRange(cidrNet *net.IPNet) (net.IP, net.IP) {
	if cidrNet == nil {
		return nil, nil
	}
	ip := cidrNet.IP.To4()
	if ip == nil {
		return nil, nil
	}
	mask := cidrNet.Mask
	if len(mask) != 4 {
		return nil, nil
	}

	ipVal := ipToUint32(ip)
	maskVal := uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
	networkVal := ipVal & maskVal
	broadcastVal := networkVal | ^maskVal

	startUsable := networkVal + 1
	endUsable := broadcastVal - 1
	if startUsable > endUsable {
		startUsable = networkVal
		endUsable = broadcastVal
	}

	return uint32ToIP(startUsable), uint32ToIP(endUsable)
}

func uint32ToIP(val uint32) net.IP {
	return net.IPv4(byte(val>>24), byte(val>>16), byte(val>>8), byte(val)).To4()
}

// IsInDHCPRange checks if the given IP address falls within the specified DHCP range.
// Supports:
// - Prefix range: "192.168.0.100-200" (start IP with end host number)
// - Full IP range: "192.168.0.100-192.168.0.200"
// - Last-octet range: "100-200"
// - Multiple ranges separated by comma/newline/semicolon (e.g. "192.168.0.100-200, 192.168.1.150-200")
func IsInDHCPRange(ipStr string, dhcpRange string) bool {
	dhcpRange = strings.TrimSpace(dhcpRange)
	if dhcpRange == "" || ipStr == "" {
		return false
	}

	targetIP := net.ParseIP(ipStr).To4()
	if targetIP == nil {
		return false
	}
	targetVal := ipToUint32(targetIP)
	lastOctet := int(targetIP[3])

	parts := splitDHCPRangeParts(dhcpRange)
	for _, p := range parts {
		item, err := parseDHCPRangeItem(p)
		if err != nil || item == nil {
			continue
		}

		if item.isFullIP {
			if item.startVal <= targetVal && targetVal <= item.endVal {
				return true
			}
		} else if item.isOctetOnly {
			if item.startOctet <= lastOctet && lastOctet <= item.endOctet {
				return true
			}
		}
	}

	return false
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// ValidateDHCPRange validates the format and CIDR subnet containment of dhcpRange.
// Returns nil if valid or empty. Returns a detailed, user-friendly error if invalid.
func ValidateDHCPRange(dhcpRange string, cidr string) error {
	dhcpRange = strings.TrimSpace(dhcpRange)
	if dhcpRange == "" {
		return nil
	}

	var cidrNet *net.IPNet
	var baseIP net.IP
	var subRangeInfo string
	if cidr != "" {
		ip, netw, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("CIDR形式が不正です: %s", cidr)
		}
		cidrNet = netw
		baseIP = ip.To4()
		minIP, maxIP := calcSubnetRange(cidrNet)
		if minIP != nil && maxIP != nil {
			subRangeInfo = fmt.Sprintf(" (有効範囲: %s 〜 %s)", minIP.String(), maxIP.String())
		}
	}

	parts := splitDHCPRangeParts(dhcpRange)
	if len(parts) == 0 {
		return nil
	}

	for _, p := range parts {
		item, err := parseDHCPRangeItem(p)
		if err != nil {
			return err
		}
		if item == nil {
			continue
		}

		if cidrNet != nil {
			if item.isFullIP {
				if !cidrNet.Contains(item.startIP) {
					return fmt.Errorf("DHCPレンジ「%s」の開始IP (%s) はセグメントのサブネット (%s%s) に含まれていません", p, item.startIP.String(), cidr, subRangeInfo)
				}
				if !cidrNet.Contains(item.endIP) {
					return fmt.Errorf("DHCPレンジ「%s」の終了IP (%s) はセグメントのサブネット (%s%s) に含まれていません", p, item.endIP.String(), cidr, subRangeInfo)
				}
			} else if item.isOctetOnly {
				if baseIP != nil {
					checkStartIP := net.IPv4(baseIP[0], baseIP[1], baseIP[2], byte(item.startOctet))
					checkEndIP := net.IPv4(baseIP[0], baseIP[1], baseIP[2], byte(item.endOctet))
					if !cidrNet.Contains(checkStartIP) {
						return fmt.Errorf("DHCPレンジ「%s」の開始ホスト (%s) はセグメントのサブネット (%s%s) に含まれていません", p, checkStartIP.String(), cidr, subRangeInfo)
					}
					if !cidrNet.Contains(checkEndIP) {
						return fmt.Errorf("DHCPレンジ「%s」の終了ホスト (%s) はセグメントのサブネット (%s%s) に含まれていません", p, checkEndIP.String(), cidr, subRangeInfo)
					}
				}
			}
		}
	}

	return nil
}

// GuessDHCPRange estimates a probable DHCP pool range based on detected client/Wi-Fi host IPs
func GuessDHCPRange(hosts []*Host, cidr string) string {
	if len(hosts) == 0 {
		return "100-200"
	}

	var octets []int
	for _, h := range hosts {
		ip := net.ParseIP(h.IP).To4()
		if ip == nil {
			continue
		}
		oct := int(ip[3])
		// Exclude router (.1), broadcast (.255), and typical network devices (.254)
		if oct <= 1 || oct >= 254 {
			continue
		}

		// Give priority to Wi-Fi devices, smartphones, and computers
		if h.ConnectionType() == "wifi" || strings.Contains(strings.ToLower(h.VendorModel), "apple") || strings.Contains(strings.ToLower(h.OSVendor), "android") || strings.Contains(strings.ToLower(h.OSVendor), "windows") {
			octets = append(octets, oct)
		}
	}

	if len(octets) == 0 {
		// Fallback to non-infrastructure devices
		for _, h := range hosts {
			ip := net.ParseIP(h.IP).To4()
			if ip == nil {
				continue
			}
			oct := int(ip[3])
			if oct > 10 && oct < 250 {
				octets = append(octets, oct)
			}
		}
	}

	if len(octets) == 0 {
		return "100-200"
	}

	sort.Ints(octets)
	minOct := octets[0]
	maxOct := octets[len(octets)-1]

	// Round to intuitive bounds (e.g. min 105 -> 100, max 165 -> 200)
	var startBound, endBound int
	if minOct >= 100 {
		startBound = 100
	} else if minOct >= 50 {
		startBound = 50
	} else if minOct >= 2 {
		startBound = 2
	} else {
		startBound = 100
	}

	if maxOct <= 100 && startBound < 100 {
		endBound = 100
	} else if maxOct <= 150 {
		endBound = 150
	} else if maxOct <= 200 {
		endBound = 200
	} else {
		endBound = 250
	}

	if startBound >= endBound {
		return "100-200"
	}

	return fmt.Sprintf("%d-%d", startBound, endBound)
}

// ToggleHostDHCP toggles the is_dhcp status of a host
func (db *DB) ToggleHostDHCP(ip string) (bool, error) {
	host, err := db.GetHost(ip)
	if err != nil {
		return false, err
	}
	if host == nil {
		return false, fmt.Errorf("host not found: %s", ip)
	}

	newStatus := !host.IsDHCP
	_, err = db.Exec("UPDATE hosts SET is_dhcp = ? WHERE ip = ?", newStatus, ip)
	return newStatus, err
}

// AutoAdjustSegmentDHCPRange recalculates and updates the segment's DHCP range
// based on hosts explicitly marked as is_dhcp=true and Wi-Fi clients
func (db *DB) AutoAdjustSegmentDHCPRange(segID int64) (string, error) {
	seg, err := db.GetSegment(segID)
	if err != nil {
		return "", err
	}
	if seg == nil {
		return "", fmt.Errorf("segment not found: %d", segID)
	}

	// Skip auto-adjustment if the user has manually fixed the DHCP range
	if seg.IsDHCPManual {
		return seg.DHCPRange, nil
	}

	hosts, err := db.ListHosts(&segID, false)
	if err != nil {
		return "", err
	}

	// Also find any hosts matching by CIDR if segment_id wasn't set
	if seg.CIDR != "" {
		allHosts, _ := db.ListHosts(nil, false)
		_, cidrNet, err := net.ParseCIDR(seg.CIDR)
		if err == nil {
			existingIPs := make(map[string]bool)
			for _, h := range hosts {
				existingIPs[h.IP] = true
			}
			for _, h := range allHosts {
				if !existingIPs[h.IP] {
					if pIP := net.ParseIP(h.IP); pIP != nil && cidrNet.Contains(pIP) {
						hosts = append(hosts, h)
					}
				}
			}
		}
	}

	// Find DHCP-marked hosts or Wi-Fi hosts
	var dhcpHosts []*Host
	for _, h := range hosts {
		if h.IsDHCP || h.ConnectionType() == "wifi" {
			dhcpHosts = append(dhcpHosts, h)
		}
	}

	if len(dhcpHosts) == 0 {
		return seg.DHCPRange, nil
	}

	newRange := GuessDHCPRange(dhcpHosts, seg.CIDR)
	if newRange != "" && newRange != seg.DHCPRange {
		seg.DHCPRange = newRange
		_ = db.UpdateSegment(seg)
	}
	return newRange, nil
}

// UpdateHostExtendedProbes updates host's open ports, web title, UPnP, and TLS details after an on-demand probe
func (db *DB) UpdateHostExtendedProbes(ip string, openPorts, httpTitle, upnpName, upnpModel, upnpSerial, tlsSubj string, tlsExp *time.Time) error {
	query := `
	UPDATE hosts SET
		open_ports = ?,
		http_title = ?,
		upnp_name = CASE WHEN ? != '' THEN ? ELSE upnp_name END,
		upnp_model = CASE WHEN ? != '' THEN ? ELSE upnp_model END,
		upnp_serial = CASE WHEN ? != '' THEN ? ELSE upnp_serial END,
		tls_subject = CASE WHEN ? != '' THEN ? ELSE tls_subject END,
		tls_expiry = CASE WHEN ? IS NOT NULL THEN ? ELSE tls_expiry END,
		last_seen = CURRENT_TIMESTAMP
	WHERE ip = ?
	`
	_, err := db.Exec(query,
		openPorts, httpTitle,
		upnpName, upnpName,
		upnpModel, upnpModel,
		upnpSerial, upnpSerial,
		tlsSubj, tlsSubj,
		tlsExp, tlsExp,
		ip,
	)
	return err
}
