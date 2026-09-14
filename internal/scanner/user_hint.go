package scanner

import (
	"regexp"
	"strings"
)

var (
	// Matches "Taro's MacBook", "田中's iPhone", "Alice’s PC"
	reApostropheS = regexp.MustCompile(`(?i)^([a-zA-Z0-9\p{Han}\p{Hiragana}\p{Katakana}_-]+)['’]s?\s+.*$`)
	// Matches "田中 の iPhone", "Taro-no-iPhone", "taro_no_macbook"
	reNoDevice = regexp.MustCompile(`(?i)^([a-zA-Z0-9\p{Han}\p{Hiragana}\p{Katakana}]+)[-_ ](?:no|の)[-_ ].*$`)
	// Matches "pc-suzuki", "mac-yamada", "win-tanaka"
	reDevicePrefix = regexp.MustCompile(`(?i)^(?:pc|mac|mbp|win|note|pad)[-_]([a-zA-Z0-9\p{Han}\p{Hiragana}\p{Katakana}]{2,20})$`)
	// Matches "suzuki-pc", "tanaka-laptop", "yamada-mac", "sato-mbp"
	reDeviceSuffix = regexp.MustCompile(`(?i)^([a-zA-Z0-9\p{Han}\p{Hiragana}\p{Katakana}]{2,20})[-_](?:pc|laptop|mac|mbp|win|note|pad|iphone|ipad|android)$`)
	// Matches Windows default random desktop IDs like "ABC1234", "7K9L2MZ"
	reWinRandomID = regexp.MustCompile(`^[A-Z0-9]{6,8}$`)
)

// Generic machine / vendor names that should NOT be treated as user hints
var genericNamesBlacklist = map[string]bool{
	"desktop":   true,
	"laptop":    true,
	"computer":  true,
	"work":      true,
	"home":      true,
	"office":    true,
	"guest":     true,
	"visitor":   true,
	"unknown":   true,
	"admin":     true,
	"root":      true,
	"server":    true,
	"router":    true,
	"gateway":   true,
	"switch":    true,
	"printer":   true,
	"ap":        true,
	"nas":       true,
	"wifi":      true,
	"lan":       true,
	"device":    true,
	"iphone":    true,
	"ipad":      true,
	"macbook":   true,
	"android":   true,
	"galaxy":    true,
	"pixel":     true,
	"windows":   true,
	"linux":     true,
	"apple":     true,
	"test":      true,
	"demo":      true,
	"local":     true,
	"localhost": true,
}

// ExtractUserHint attempts to extract a person's name or owner hint from host signals
func ExtractUserHint(hostname, mdnsModel, upnpName string) string {
	candidates := []string{mdnsModel, upnpName, hostname}

	for _, raw := range candidates {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}

		// Strip local domain suffix (.local, .lan, etc.)
		if dotIdx := strings.Index(trimmed, "."); dotIdx != -1 {
			trimmed = trimmed[:dotIdx]
		}

		// 1. "Taro's MacBook" or "田中's iPhone"
		if matches := reApostropheS.FindStringSubmatch(trimmed); len(matches) > 1 {
			name := cleanCandidateName(matches[1])
			if isValidUserHint(name) {
				return name
			}
		}

		// 2. "田中 の iPhone" or "Taro-no-iPhone"
		if matches := reNoDevice.FindStringSubmatch(trimmed); len(matches) > 1 {
			name := cleanCandidateName(matches[1])
			if isValidUserHint(name) {
				return name
			}
		}

		// 3. "pc-suzuki"
		if matches := reDevicePrefix.FindStringSubmatch(trimmed); len(matches) > 1 {
			name := cleanCandidateName(matches[1])
			if isValidUserHint(name) {
				return name
			}
		}

		// 4. "suzuki-pc"
		if matches := reDeviceSuffix.FindStringSubmatch(trimmed); len(matches) > 1 {
			name := cleanCandidateName(matches[1])
			if isValidUserHint(name) {
				return name
			}
		}
	}

	return ""
}

func cleanCandidateName(s string) string {
	s = strings.Trim(s, "-_ '’")
	// If camelCase or PascalCase, keep it as is; or title-case if ascii lowercase
	return s
}

func isValidUserHint(name string) bool {
	if len(name) < 2 || len(name) > 30 {
		return false
	}
	lower := strings.ToLower(name)
	if genericNamesBlacklist[lower] {
		return false
	}
	// Reject hex strings / MAC-like strings (e.g. "a1b2c3d4e5f6")
	if len(name) >= 8 && isHexOnly(lower) {
		return false
	}
	// Reject generic windows auto-generated strings like "DESKTOP-ABC123"
	if strings.HasPrefix(lower, "desktop-") || strings.HasPrefix(lower, "laptop-") || reWinRandomID.MatchString(name) {
		return false
	}
	return true
}

func isHexOnly(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
