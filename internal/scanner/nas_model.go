package scanner

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// Synology patterns: DSxxx, RSxxx, FSxxx, SAxxx, UCxxx, DVAxxx, BeeStation
	reSynologyDetailedModel = regexp.MustCompile(`(?i)\b(DS\d{3,4}[A-Za-z0-9]*(?:\+)?|RS\d{3,4}[A-Za-z0-9]*(?:\+)?|FS\d{4}[A-Za-z0-9]*|SA\d{4}[A-Za-z0-9]*|UC\d{4}[A-Za-z0-9]*|DVA\d{4}[A-Za-z0-9]*|BST\d{3}[A-Za-z0-9-]*|BeeStation|RT\d{4}[a-z]*|WRX\d{3}[a-z]*)`)

	// QNAP patterns: TS-xxx, TVS-xxx, TBS-xxx, HS-xxx
	reQNAPDetailedModel = regexp.MustCompile(`(?i)\b(TS-[A-Za-z0-9+-]+|TVS-[A-Za-z0-9+-]+|TBS-[A-Za-z0-9+-]+|HS-[A-Za-z0-9+-]+)\b`)

	// I-O DATA LANDISK patterns: HDL-xxx, HDL2-xxx, HDL4-xxx, HDL6-xxx
	reIODataNASModel = regexp.MustCompile(`(?i)\b(HDL\d?-[A-Za-z0-9]+|HDL-[A-Za-z0-9]+)\b`)

	// Buffalo TeraStation & LinkStation patterns: TSxxxx, LSxxxx, WSxxxx
	reBuffaloNASModel = regexp.MustCompile(`(?i)\b(TS\d{4}[A-Za-z0-9-]*|LS\d{3,4}[A-Za-z0-9-]*|WS\d{4}[A-Za-z0-9-]*)\b`)

	// ASUSTOR patterns: ASxxxx, FSxxxx, Lockerstor, Drivestor, Nimbustor
	reAsustorModel = regexp.MustCompile(`(?i)\b(AS\d{4}[A-Za-z0-9]*|FS\d{4}[A-Za-z0-9]*|Lockerstor\s+\d+|Drivestor\s+\d+|Nimbustor\s+\d+)\b`)

	// TerraMaster patterns: F2-xxx, F4-xxx, F5-xxx, T6-xxx, etc.
	reTerraMasterModel = regexp.MustCompile(`(?i)\b(F\d-[A-Za-z0-9-]+|T\d-[A-Za-z0-9-]+|D\d-[A-Za-z0-9-]+)\b`)
)

// ResolveNASModel extracts and formats precise NAS hardware model strings (Synology, QNAP, I-O DATA, Buffalo, ASUSTOR, TerraMaster)
func ResolveNASModel(upnpModel, upnpName, httpTitle, hostname, vendor string) string {
	combined := fmt.Sprintf("%s %s %s %s %s", upnpModel, upnpName, httpTitle, hostname, vendor)
	combinedLower := strings.ToLower(combined)
	vendorLower := strings.ToLower(vendor)

	// 1. Synology
	if strings.Contains(combinedLower, "synology") || strings.Contains(combinedLower, "diskstation") ||
		strings.Contains(combinedLower, "rackstation") || strings.Contains(vendorLower, "synology") {
		if m := reSynologyDetailedModel.FindString(combined); m != "" {
			cleanModel := strings.TrimSpace(m)
			// Normalize capitalization for standard series (e.g. ds920+ -> DS920+)
			cleanUpper := strings.ToUpper(cleanModel)
			return fmt.Sprintf("Synology %s", cleanUpper)
		}
		if strings.Contains(combinedLower, "rackstation") {
			return "Synology RackStation"
		}
		return "Synology DiskStation"
	}

	// 2. QNAP
	if strings.Contains(combinedLower, "qnap") || strings.Contains(combinedLower, "qts") ||
		strings.Contains(combinedLower, "quts") || strings.Contains(vendorLower, "qnap") {
		if m := reQNAPDetailedModel.FindString(combined); m != "" {
			cleanModel := strings.ToUpper(strings.TrimSpace(m))
			return fmt.Sprintf("QNAP %s", cleanModel)
		}
		return "QNAP Turbo NAS"
	}

	// 3. I-O DATA LANDISK
	if strings.Contains(combinedLower, "landisk") || strings.Contains(combinedLower, "i-o data") ||
		strings.Contains(combinedLower, "iodata") || strings.Contains(vendorLower, "i-o data") {
		if m := reIODataNASModel.FindString(combined); m != "" {
			return fmt.Sprintf("I-O DATA %s", strings.ToUpper(strings.TrimSpace(m)))
		}
		if strings.Contains(combinedLower, "landisk") {
			return "I-O DATA LANDISK"
		}
	}

	// 4. Buffalo TeraStation / LinkStation
	if strings.Contains(combinedLower, "terastation") || strings.Contains(combinedLower, "linkstation") ||
		(strings.Contains(vendorLower, "buffalo") && (strings.Contains(combinedLower, "ts") || strings.Contains(combinedLower, "ls"))) {
		if m := reBuffaloNASModel.FindString(combined); m != "" {
			return fmt.Sprintf("Buffalo %s", strings.ToUpper(strings.TrimSpace(m)))
		}
		if strings.Contains(combinedLower, "terastation") {
			return "Buffalo TeraStation"
		} else if strings.Contains(combinedLower, "linkstation") {
			return "Buffalo LinkStation"
		}
	}

	// 5. ASUSTOR
	if strings.Contains(combinedLower, "asustor") || strings.Contains(vendorLower, "asustor") {
		if m := reAsustorModel.FindString(combined); m != "" {
			return fmt.Sprintf("ASUSTOR %s", strings.TrimSpace(m))
		}
		return "ASUSTOR NAS"
	}

	// 6. TerraMaster
	if strings.Contains(combinedLower, "terramaster") || strings.Contains(vendorLower, "terramaster") {
		if m := reTerraMasterModel.FindString(combined); m != "" {
			return fmt.Sprintf("TerraMaster %s", strings.ToUpper(strings.TrimSpace(m)))
		}
		return "TerraMaster NAS"
	}

	return ""
}
