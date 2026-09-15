package scanner

import (
	"regexp"
	"strings"
)

var (
	// Matches "Taro's MacBook", "田中's iPhone", "Alice’s PC", "taro's-macbook", "Hiroshi's MacBook Pro"
	reApostropheS = regexp.MustCompile(`(?i)^([a-zA-Z0-9\p{Han}\p{Hiragana}\p{Katakana}_.-]+)['’]s?\s*[-_ ]?.*$`)
	// Matches "田中 の iPhone", "田中太郎のMacBook", "Taro-no-iPhone", "taro_no_macbook", "佐藤のiPad"
	reNoDevice = regexp.MustCompile(`(?i)^([a-zA-Z0-9\p{Han}\p{Hiragana}\p{Katakana}]+)[-_ ]?(?:no|の)[-_ ]?.*$`)
	// Matches "taros-macbook-pro", "hiroshis-mac", "tanakas-pc" (hyphenated 's suffix)
	reHyphenS = regexp.MustCompile(`(?i)^([a-zA-Z0-9\p{Han}\p{Hiragana}\p{Katakana}]{2,20})s[-_](?:macbook|mac|mbp|imac|laptop|pc|iphone|ipad|air|mini|desktop).*$`)
	// Matches "pc-suzuki", "mac-yamada", "win-tanaka", "mbp-hiroshi", "air-taro", "pad-ken"
	reDevicePrefix = regexp.MustCompile(`(?i)^(?:pc|mac|mbp|imac|air|mini|win|note|pad)[-_]([a-zA-Z0-9\p{Han}\p{Hiragana}\p{Katakana}._-]{2,20})$`)
	// Matches "suzuki-pc", "tanaka-laptop", "yamada-mac", "sato-mbp", "hiroshi-imac", "taro-air", "hiroshi-m1", "hiroshi-m2", "hiroshi-m3", "hiroshi-m4", "hiroshi-macbook"
	reDeviceSuffix = regexp.MustCompile(`(?i)^([a-zA-Z0-9\p{Han}\p{Hiragana}\p{Katakana}._-]{2,20})[-_](?:pc|laptop|mac|mbp|imac|air|mini|win|note|pad|iphone|ipad|android|m1|m2|m3|m4|macbook|macbookpro|macbookair)$`)
	// Matches "MacBook Pro (Hiroshi)", "iPhone (田中)", "iPad (Taro)"
	reDeviceWithParenName = regexp.MustCompile(`(?i)^(?:macbook|macbook pro|macbook air|imac|mac mini|mac studio|mac pro|iphone|ipad|pc|laptop|desktop|android)\s*[\(\[\{]([a-zA-Z0-9\p{Han}\p{Hiragana}\p{Katakana}._ -]{2,20})[\)\]\}]$`)
	// Matches "Hiroshi (MacBook Pro)", "田中 (iPhone)"
	reNameWithParenDevice = regexp.MustCompile(`(?i)^([a-zA-Z0-9\p{Han}\p{Hiragana}\p{Katakana}._ -]{2,20})\s*[\(\[\{](?:macbook|macbook pro|macbook air|imac|mac mini|mac studio|mac pro|iphone|ipad|pc|laptop|desktop|android)[\)\]\}]$`)
	// Matches "MacBook-de-Taro", "MacBook-Pro-de-Jean" (French/Spanish)
	reDeDevice = regexp.MustCompile(`(?i)^.*[-_ ]de[-_ ]([a-zA-Z0-9\p{Han}\p{Hiragana}\p{Katakana}]{2,20})$`)
	// Matches Windows default random desktop IDs like "7K9L2MZ", "9B4X2A" (must contain both letters and digits)
	reWinRandomID = regexp.MustCompile(`^(?:[A-Z0-9]*[0-9][A-Z0-9]*[A-Z]|[A-Z0-9]*[A-Z][A-Z0-9]*[0-9])[A-Z0-9]{4,10}$`)
)

// Generic machine / vendor names that should NOT be treated as user hints
var genericNamesBlacklist = map[string]bool{
	"desktop":         true,
	"laptop":          true,
	"computer":        true,
	"work":            true,
	"home":            true,
	"office":          true,
	"guest":           true,
	"visitor":         true,
	"unknown":         true,
	"admin":           true,
	"root":            true,
	"server":          true,
	"router":          true,
	"gateway":         true,
	"switch":          true,
	"printer":         true,
	"ap":              true,
	"nas":             true,
	"wifi":            true,
	"lan":             true,
	"device":          true,
	"iphone":          true,
	"ipad":            true,
	"macbook":         true,
	"macbookpro":      true,
	"macbookair":      true,
	"macbook pro":     true,
	"macbook air":     true,
	"imac":            true,
	"mac mini":        true,
	"mac studio":      true,
	"mac pro":         true,
	"android":         true,
	"galaxy":          true,
	"pixel":           true,
	"windows":         true,
	"linux":           true,
	"apple":           true,
	"test":            true,
	"demo":            true,
	"local":           true,
	"localhost":       true,
}

// ExtractUserHint attempts to extract a person's name or owner hint from host signals
func ExtractUserHint(sources ...string) string {
	for _, raw := range sources {
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

		// 2. "田中 の iPhone" or "田中太郎のMacBook" or "Taro-no-iPhone"
		if matches := reNoDevice.FindStringSubmatch(trimmed); len(matches) > 1 {
			name := cleanCandidateName(matches[1])
			if isValidUserHint(name) {
				return name
			}
		}

		// 3. "MacBook Pro (Hiroshi)" or "iPhone (田中)"
		if matches := reDeviceWithParenName.FindStringSubmatch(trimmed); len(matches) > 1 {
			name := cleanCandidateName(matches[1])
			if isValidUserHint(name) {
				return name
			}
		}

		// 4. "Hiroshi (MacBook Pro)" or "田中 (iPhone)"
		if matches := reNameWithParenDevice.FindStringSubmatch(trimmed); len(matches) > 1 {
			name := cleanCandidateName(matches[1])
			if isValidUserHint(name) {
				return name
			}
		}

		// 5. "pc-suzuki"
		if matches := reDevicePrefix.FindStringSubmatch(trimmed); len(matches) > 1 {
			name := cleanCandidateName(matches[1])
			if isValidUserHint(name) {
				return name
			}
		}

		// 6. "suzuki-pc" or "hiroshi-m1"
		if matches := reDeviceSuffix.FindStringSubmatch(trimmed); len(matches) > 1 {
			name := cleanCandidateName(matches[1])
			if isValidUserHint(name) {
				return name
			}
		}

		// 7. "taros-macbook-pro"
		if matches := reHyphenS.FindStringSubmatch(trimmed); len(matches) > 1 {
			name := cleanCandidateName(matches[1])
			if isValidUserHint(name) {
				return name
			}
		}

		// 8. "MacBook-de-Taro"
		if matches := reDeDevice.FindStringSubmatch(trimmed); len(matches) > 1 {
			name := cleanCandidateName(matches[1])
			if isValidUserHint(name) {
				return name
			}
		}

		// 9. Direct standalone user name (e.g. from NetBIOS <03> Messenger entry or DHCP username)
		if isValidStandaloneUser(trimmed) {
			return cleanCandidateName(trimmed)
		}
	}

	return ""
}

func cleanCandidateName(s string) string {
	s = strings.Trim(s, "-_ '’")
	return s
}

func isValidUserHint(name string) bool {
	if len(name) < 2 || len(name) > 30 {
		return false
	}
	lower := strings.ToLower(name)
	if isBlacklistedGenericName(lower) {
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

func isBlacklistedGenericName(lower string) bool {
	if genericNamesBlacklist[lower] {
		return true
	}
	tokens := strings.FieldsFunc(lower, func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == ' '
	})
	for _, tok := range tokens {
		if genericNamesBlacklist[tok] {
			return true
		}
	}
	return false
}

func isValidStandaloneUser(name string) bool {
	if !isValidUserHint(name) {
		return false
	}
	// Standalone username should not be hyphenated machine name
	if strings.Contains(name, "-") || strings.Contains(name, "_") {
		return false
	}
	lower := strings.ToLower(name)
	if lower == "workgroup" || lower == "domain" || strings.HasPrefix(lower, "win") || strings.HasPrefix(lower, "pc") || strings.HasPrefix(lower, "mac") || strings.HasPrefix(lower, "dhcp") {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= 0x4e00 && r <= 0x9fff) || (r >= 0x3040 && r <= 0x309f) || (r >= 0x30a0 && r <= 0x30ff) {
			return true
		}
	}
	return false
}

func isHexOnly(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
