package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var titleRegexp = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

var (
	// Netgear: e.g. WAX610, WAC510, GS108Tv3, RAX120, Orbi RBK752, MS510TX
	reNetgearModel  = regexp.MustCompile(`(?i)\b(WAX\d{3}[A-Z0-9]*|WAC\d{3}[A-Z0-9]*|WNDR\d{4}[A-Z0-9]*|R\d{4}[A-Z0-9]*|RAX\d{2,3}[A-Z0-9]*|XR\d{3,4}|RBK\d{2,3}|RBR\d{2,3}|RBS\d{2,3}|SXK\d{2,3}|SXR\d{2,3}|GS\d{3}[A-Z0-9]*|MS\d{3}[A-Z0-9]*|XS\d{3}[A-Z0-9]*|M4250[A-Z0-9-]*|M4300[A-Z0-9-]*|PR\d{3}|FS\d{3}[A-Z0-9]*)\b`)
	reNetgearPrefix = regexp.MustCompile(`(?i)NETGEAR\s+([A-Z0-9-]+)`)

	// Yamaha: e.g. RTX830, RTX1210, NVR510, WLX212, SWX2210-8G
	reYamahaModel = regexp.MustCompile(`(?i)\b(RTX\d{3,4}[A-Z]*|NVR\d{3}[A-Z]*|WLX\d{3}[A-Z]*|SWX\d{4}-\d+[A-Z]*|SWX\d{4})\b`)

	// Fortinet / FortiGate: e.g. FortiGate-60F, FortiWiFi-60F, FortiSwitch-124F
	reFortinetModel = regexp.MustCompile(`(?i)\b(FortiGate[\s-]*\d+[A-Z0-9]*|FortiWiFi[\s-]*\d+[A-Z0-9]*|FortiSwitch[\s-]*\d+[A-Z0-9]*|FortiAP[\s-]*\d+[A-Z0-9]*)\b`)

	// Buffalo: e.g. WAPM-1266R, WSR-3200AX4S, TS5410DN, BS-GS2016
	reBuffaloModel = regexp.MustCompile(`(?i)\b(WXR-\d+[A-Z0-9]+|WSR-\d+[A-Z0-9]+|WVR-\d+[A-Z0-9]+|WAPM-[A-Z0-9-]+|WAPS-[A-Z0-9-]+|TS\d{4}[A-Z0-9]*|LS\d{3}[A-Z0-9]*|BS-GS\d+[A-Z]*|BS-MS\d+[A-Z]*)\b`)

	// Cisco & Meraki: e.g. Catalyst 2960, CBS350, Meraki MR36, Meraki MS120
	reCiscoModel = regexp.MustCompile(`(?i)\b(Catalyst\s+\d+[A-Z]*|CBS\d{3}[A-Z0-9-]*|SG\d{3}[A-Z0-9-]*|Meraki\s+[A-Z]{2}\d{2}[A-Z0-9]*|MR\d{2}[A-Z0-9]*|MS\d{2,3}[A-Z0-9]*|MX\d{2}[A-Z0-9]*)\b`)

	// Aruba: e.g. Instant On AP22, Instant On 1930, AP-505
	reArubaModel = regexp.MustCompile(`(?i)\b(Instant\s+On\s+AP\d+[A-Z0-9]*|Instant\s+On\s+\d{4}[A-Z]*|Aruba\s+AP-\d+[A-Z0-9]*|AP-\d{3}[A-Z0-9]*|Aruba\s+CX\s+\d+)\b`)

	// Mist: e.g. Mist AP43, AP41, AP45
	reMistModel = regexp.MustCompile(`(?i)\b(Mist\s+AP\d+|AP41|AP43|AP45|AP32|AP33|AP34|AP12|AP21)\b`)

	// TP-Link: e.g. EAP610, TL-SG108E, Archer AX55, Deco X50, ER605
	reTPLinkModel = regexp.MustCompile(`(?i)\b(EAP\d{3}[A-Z0-9-]*|TL-SG\d{3,4}[A-Z0-9-]*|Deco\s+[A-Z0-9]+|Archer\s+[A-Z0-9]+|ER\d{3,4}[A-Z0-9]*)\b`)

	// Allied Telesis: e.g. AT-GS950, AT-x230, CentreCOM GS908M
	reAlliedModel = regexp.MustCompile(`(?i)\b(AT-GS\d{3}[A-Z0-9/-]*|AT-x\d{3}[A-Z0-9/-]*|CentreCOM\s+[A-Z0-9/-]+)\b`)

	// Synology / QNAP: e.g. DS920+, TS-453D
	reSynologyModel = regexp.MustCompile(`(?i)\b(DS\d{3,4}[A-Za-z0-9]*(?:\+)?|RS\d{3,4}[A-Za-z0-9]*(?:\+)?)`)
	reQNAPModel     = regexp.MustCompile(`(?i)\b(TS-\d{3,4}[A-Za-z0-9]*(?:\+)?|TVS-\d{3,4}[A-Za-z0-9]*(?:\+)?)`)

	// Printers / MFPs
	reCanonModel     = regexp.MustCompile(`(?i)\b(imageRUNNER\s+ADVANCE\s+[A-Z0-9-]+|iR-ADV\s+[A-Z0-9-]+|LBP\d{3,4}[A-Z]*)\b`)
	reRicohModel     = regexp.MustCompile(`(?i)\b(RICOH\s+MP\s+C\d{3,4}[A-Z]*|RICOH\s+IM\s+C\d{3,4}[A-Z]*|RICOH\s+SP\s+[A-Z0-9]+)\b`)
	reFujiXeroxModel = regexp.MustCompile(`(?i)\b(ApeosPort-[A-Z0-9\s]+|DocuCentre-[A-Z0-9\s]+|Apeos\s+[A-Z0-9-]+)\b`)
	reKyoceraModel   = regexp.MustCompile(`(?i)\b(TASKalfa\s+\d+[a-z]*|ECOSYS\s+[A-Za-z0-9-]+)\b`)
	reBrotherModel   = regexp.MustCompile(`(?i)\b(MFC-[A-Z0-9]+|HL-[A-Z0-9]+|DCP-[A-Z0-9]+)\b`)
	reEpsonModel     = regexp.MustCompile(`(?i)\b(PX-[A-Z0-9]+|EW-[A-Z0-9]+|LP-[A-Z0-9]+|WorkForce\s+[A-Za-z0-9-]+)\b`)

	// Cameras (i-PRO, Axis, Hikvision, Dahua)
	reIProModel      = regexp.MustCompile(`(?i)\b(WV-S\d{4}[A-Z]*|WV-U\d{4}[A-Z]*|WV-X\d{4}[A-Z]*|WJ-NX\d{3}[A-Z]*)\b`)
	reAxisModel      = regexp.MustCompile(`(?i)\b(AXIS\s+[MPQ]\d{4}[A-Z-]*)\b`)
	reHikvisionModel = regexp.MustCompile(`(?i)\b(DS-2CD\d[A-Z0-9-]+|DS-76\d{2}[A-Z0-9-]+|DS-77\d{2}[A-Z0-9-]+)\b`)
	reDahuaModel     = regexp.MustCompile(`(?i)\b(IPC-H[DF]W\d[A-Z0-9-]+|NVR\d{4}[A-Z0-9-]+)\b`)

	// IP Phones
	reYealinkModel        = regexp.MustCompile(`(?i)\b(SIP-T\d{2}[A-Z]*|Yealink\s+SIP-T\d{2}[A-Z]*)\b`)
	reGrandstreamModel    = regexp.MustCompile(`(?i)\b(GRP\d{4}[A-Z]*|GXP\d{4}[A-Z]*|GXV\d{4}[A-Z]*|WP\d{3})\b`)
	rePanasonicPhoneModel = regexp.MustCompile(`(?i)\b(KX-HDV\d{3}|KX-UT\d{3}|KX-TGP\d{3})\b`)
)

// ExtractWebTitle probes HTTP/HTTPS ports to fetch HTML <title> or server brand banner
func ExtractWebTitle(ip string, openPorts string) string {
	title, _ := ExtractWebTitleAndModel(ip, openPorts, "")
	return title
}

// ExtractWebTitleAndModel probes HTTP/HTTPS ports to fetch HTML <title> and inferred model name
func ExtractWebTitleAndModel(ip string, openPorts string, currentVendor string) (title string, inferredModel string) {
	ports := []int{80, 443, 8080, 8443, 5000}
	portSet := map[int]bool{80: true, 443: true, 8080: true, 8443: true, 5000: true}

	if openPorts != "" {
		for _, part := range strings.Split(openPorts, ",") {
			sub := strings.Split(strings.TrimSpace(part), ":")
			if len(sub) > 0 {
				if p, err := strconv.Atoi(sub[0]); err == nil && p > 0 {
					if !portSet[p] {
						portSet[p] = true
						ports = append(ports, p)
					}
				}
			}
		}
	}

	client := &http.Client{
		Timeout: 350 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	for _, port := range ports {
		// Only probe if openPorts contains the port or if openPorts is empty (heuristic)
		portStr := fmt.Sprintf("%d", port)
		if openPorts != "" && !strings.Contains(openPorts, portStr) {
			continue
		}

		schemes := []string{"http", "https"}
		if port == 443 || port == 8443 {
			schemes = []string{"https", "http"}
		}

		for _, scheme := range schemes {
			url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				continue
			}
			req.Close = true
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) lanmap/0.0.35")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			// Read up to first 16KB of response
			buf := make([]byte, 16384)
			n, _ := io.ReadFull(resp.Body, buf)
			serverHdr := resp.Header.Get("Server")
			resp.Body.Close()

			if n > 0 {
				body := string(buf[:n])
				extractedTitle := ""
				matches := titleRegexp.FindStringSubmatch(body)
				if len(matches) >= 2 {
					extractedTitle = strings.TrimSpace(matches[1])
					extractedTitle = strings.Join(strings.Fields(extractedTitle), " ")
				}

				model := InferModelFromWebResponse(extractedTitle, body, serverHdr, currentVendor)
				if model != "" {
					inferredModel = model
				}

				if extractedTitle != "" && !strings.EqualFold(extractedTitle, "404 Not Found") && !strings.EqualFold(extractedTitle, "302 Found") && !strings.EqualFold(extractedTitle, "Document Error") {
					title = extractedTitle
					return title, inferredModel
				}

				// Fallback: Check HTML body for distinct equipment signatures
				bodyLower := strings.ToLower(body)
				if strings.Contains(bodyLower, "fortigate") || strings.Contains(bodyLower, "fortinet") {
					return "FortiGate Administrative WebUI", inferredModel
				}
				if strings.Contains(bodyLower, "aruba instant") || strings.Contains(bodyLower, "instant on") {
					return "Aruba Instant On WebUI", inferredModel
				}
				if strings.Contains(bodyLower, "netgear") {
					return "NETGEAR Management WebUI", inferredModel
				}
				if strings.Contains(bodyLower, "hikvision") || strings.Contains(bodyLower, "web components") {
					return "Hikvision Web Camera", inferredModel
				}
				if strings.Contains(bodyLower, "dahua") {
					return "Dahua Web Camera", inferredModel
				}
			}

			// Fallback: If Server header is rich and distinct
			if serverHdr != "" {
				sLower := strings.ToLower(serverHdr)
				if strings.Contains(sLower, "uhttpd") {
					return "OpenWrt (uHTTPd)", inferredModel
				}
				if strings.Contains(sLower, "synology") {
					return "Synology DSM", inferredModel
				}
				if strings.Contains(sLower, "boa") || strings.Contains(sLower, "rompager") || strings.Contains(sLower, "goahead") {
					return fmt.Sprintf("Embedded Device (%s)", serverHdr), inferredModel
				}
			}
		}
	}

	return "", inferredModel
}

// InferModelFromWebResponse extracts specific vendor and model identifiers from HTML title, body, and server headers
func InferModelFromWebResponse(title, body, serverHdr, currentVendor string) string {
	combined := fmt.Sprintf("%s\n%s\n%s", title, body, serverHdr)
	combinedLower := strings.ToLower(combined)
	vendorLower := strings.ToLower(currentVendor)

	// 1. NETGEAR
	if strings.Contains(combinedLower, "netgear") || strings.Contains(vendorLower, "netgear") {
		if m := reNetgearModel.FindString(combined); m != "" {
			return fmt.Sprintf("NETGEAR %s", strings.TrimSpace(m))
		}
		if m := reNetgearPrefix.FindStringSubmatch(combined); len(m) >= 2 {
			cand := strings.TrimSpace(m[1])
			candLower := strings.ToLower(cand)
			if !strings.HasPrefix(candLower, "smart") && !strings.HasPrefix(candLower, "switch") && !strings.HasPrefix(candLower, "router") && !strings.HasPrefix(candLower, "access") && !strings.HasPrefix(candLower, "management") && !strings.HasPrefix(candLower, "prosafe") {
				return fmt.Sprintf("NETGEAR %s", cand)
			}
		}
		return "NETGEAR Device"
	}

	// 2. Yamaha
	if strings.Contains(combinedLower, "yamaha") || strings.Contains(combinedLower, "rtx") || strings.Contains(combinedLower, "nvr") || strings.Contains(combinedLower, "wlx") || strings.Contains(vendorLower, "yamaha") {
		if m := reYamahaModel.FindString(combined); m != "" {
			return fmt.Sprintf("Yamaha %s", strings.ToUpper(strings.TrimSpace(m)))
		}
	}

	// 3. Fortinet / FortiGate
	if strings.Contains(combinedLower, "fortinet") || strings.Contains(combinedLower, "fortigate") || strings.Contains(vendorLower, "fortinet") {
		if m := reFortinetModel.FindString(combined); m != "" {
			cleanModel := strings.TrimSpace(m)
			if !strings.HasPrefix(strings.ToLower(cleanModel), "fortinet") {
				return fmt.Sprintf("Fortinet %s", cleanModel)
			}
			return cleanModel
		}
		return "Fortinet FortiGate"
	}

	// 4. Buffalo
	if strings.Contains(combinedLower, "buffalo") || strings.Contains(combinedLower, "terastation") || strings.Contains(combinedLower, "linkstation") || strings.Contains(vendorLower, "buffalo") || strings.Contains(vendorLower, "melco") {
		if m := reBuffaloModel.FindString(combined); m != "" {
			return fmt.Sprintf("Buffalo %s", strings.TrimSpace(m))
		}
	}

	// 5. Cisco & Meraki
	if strings.Contains(combinedLower, "cisco") || strings.Contains(combinedLower, "meraki") || strings.Contains(vendorLower, "cisco") {
		if m := reCiscoModel.FindString(combined); m != "" {
			cleanModel := strings.TrimSpace(m)
			if !strings.HasPrefix(strings.ToLower(cleanModel), "cisco") {
				return fmt.Sprintf("Cisco %s", cleanModel)
			}
			return cleanModel
		}
	}

	// 6. Aruba (HPE)
	if strings.Contains(combinedLower, "aruba") || strings.Contains(combinedLower, "instant on") || strings.Contains(vendorLower, "aruba") || strings.Contains(vendorLower, "hewlett") {
		if m := reArubaModel.FindString(combined); m != "" {
			cleanModel := strings.TrimSpace(m)
			if !strings.HasPrefix(strings.ToLower(cleanModel), "aruba") {
				return fmt.Sprintf("Aruba %s", cleanModel)
			}
			return cleanModel
		}
	}

	// 7. Mist Systems (Juniper)
	if strings.Contains(combinedLower, "mist") || strings.Contains(vendorLower, "mist") || strings.Contains(vendorLower, "juniper") {
		if m := reMistModel.FindString(combined); m != "" {
			cleanModel := strings.TrimSpace(m)
			if strings.HasPrefix(strings.ToLower(cleanModel), "mist ") {
				return fmt.Sprintf("Mist Systems %s", cleanModel[5:])
			}
			return fmt.Sprintf("Mist Systems %s", cleanModel)
		}
	}

	// 8. TP-Link / Omada
	if strings.Contains(combinedLower, "tp-link") || strings.Contains(combinedLower, "omada") || strings.Contains(vendorLower, "tp-link") {
		if m := reTPLinkModel.FindString(combined); m != "" {
			return fmt.Sprintf("TP-Link %s", strings.TrimSpace(m))
		}
	}

	// 9. Allied Telesis
	if strings.Contains(combinedLower, "allied telesis") || strings.Contains(combinedLower, "centrecom") || strings.Contains(vendorLower, "allied") {
		if m := reAlliedModel.FindString(combined); m != "" {
			return fmt.Sprintf("Allied Telesis %s", strings.TrimSpace(m))
		}
	}

	// 10. Synology & QNAP
	if strings.Contains(combinedLower, "synology") || strings.Contains(combinedLower, "diskstation") || strings.Contains(vendorLower, "synology") {
		if m := reSynologyModel.FindStringSubmatch(combined); len(m) >= 2 {
			return fmt.Sprintf("Synology %s", strings.TrimSpace(m[1]))
		}
		if m := reSynologyModel.FindString(combined); m != "" {
			return fmt.Sprintf("Synology %s", strings.TrimSpace(m))
		}
		return "Synology NAS"
	}
	if strings.Contains(combinedLower, "qnap") || strings.Contains(vendorLower, "qnap") {
		if m := reQNAPModel.FindStringSubmatch(combined); len(m) >= 2 {
			return fmt.Sprintf("QNAP %s", strings.TrimSpace(m[1]))
		}
		if m := reQNAPModel.FindString(combined); m != "" {
			return fmt.Sprintf("QNAP %s", strings.TrimSpace(m))
		}
		return "QNAP NAS"
	}

	// 11. Printers & MFPs
	if m := reCanonModel.FindString(combined); m != "" {
		return fmt.Sprintf("Canon %s", strings.TrimSpace(m))
	}
	if m := reRicohModel.FindString(combined); m != "" {
		return strings.TrimSpace(m)
	}
	if m := reFujiXeroxModel.FindString(combined); m != "" {
		return fmt.Sprintf("Fujifilm %s", strings.TrimSpace(m))
	}
	if m := reKyoceraModel.FindString(combined); m != "" {
		return fmt.Sprintf("Kyocera %s", strings.TrimSpace(m))
	}
	if m := reBrotherModel.FindString(combined); m != "" {
		return fmt.Sprintf("Brother %s", strings.TrimSpace(m))
	}
	if m := reEpsonModel.FindString(combined); m != "" {
		return fmt.Sprintf("Epson %s", strings.TrimSpace(m))
	}

	// 12. Cameras (i-PRO, Axis, Hikvision, Dahua)
	if m := reIProModel.FindString(combined); m != "" {
		return fmt.Sprintf("i-PRO %s", strings.TrimSpace(m))
	}
	if m := reAxisModel.FindString(combined); m != "" {
		return strings.TrimSpace(m)
	}
	if m := reHikvisionModel.FindString(combined); m != "" {
		return fmt.Sprintf("Hikvision %s", strings.TrimSpace(m))
	}
	if m := reDahuaModel.FindString(combined); m != "" {
		return fmt.Sprintf("Dahua %s", strings.TrimSpace(m))
	}

	// 13. IP Phones
	if m := reYealinkModel.FindString(combined); m != "" {
		clean := strings.TrimSpace(m)
		if !strings.HasPrefix(strings.ToLower(clean), "yealink") {
			return fmt.Sprintf("Yealink %s", clean)
		}
		return clean
	}
	if m := reGrandstreamModel.FindString(combined); m != "" {
		clean := strings.TrimSpace(m)
		if !strings.HasPrefix(strings.ToLower(clean), "grandstream") {
			return fmt.Sprintf("Grandstream %s", clean)
		}
		return clean
	}
	if m := rePanasonicPhoneModel.FindString(combined); m != "" {
		return fmt.Sprintf("Panasonic %s", strings.TrimSpace(m))
	}

	return ""
}

// EnrichVendorWithModel enriches current vendor string with more detailed inferred model if available
func EnrichVendorWithModel(currentVendor, inferredModel string) string {
	if inferredModel != "" {
		return inferredModel
	}
	return currentVendor
}

// IsNICChipVendor checks if vendor is purely a component/NIC chipset manufacturer
func IsNICChipVendor(vendor string) bool {
	v := strings.ToLower(strings.TrimSpace(vendor))
	if v == "" {
		return false
	}
	nicKeywords := []string{
		"intel corporate", "intel corp", "realtek", "azurewave", "murata",
		"qualcomm", "atheros", "broadcom", "liteon", "hon hai", "foxconn",
		"chicony", "mediatek", "marvell", "asix", "microchip", "wiznet",
		"silicon labs", "texas instruments",
	}
	for _, k := range nicKeywords {
		if strings.Contains(v, k) {
			return true
		}
	}
	return false
}

// RefineVendorModel cleanses raw NIC vendors and synthesizes accurate product model or brand
func RefineVendorModel(currentVendor, mdnsModel, winModel, inferredModel, osVendor, hostname string) string {
	// 1. Highest priority: verified hardware model from mDNS or UPnP/NetBIOS/Web
	if mdnsModel != "" {
		return mdnsModel
	}
	if winModel != "" {
		return winModel
	}
	if inferredModel != "" {
		return inferredModel
	}

	// 2. Check if currentVendor is a raw NIC chip vendor (Intel, Realtek, AzureWave, etc.)
	if IsNICChipVendor(currentVendor) {
		// Infer from hostname
		hLower := strings.ToLower(hostname)
		if strings.Contains(hLower, "thinkpad") {
			return "Lenovo ThinkPad"
		} else if strings.Contains(hLower, "surface") {
			return "Microsoft Surface"
		} else if strings.Contains(hLower, "macbook") {
			return "Apple MacBook"
		} else if strings.Contains(hLower, "imac") {
			return "Apple iMac"
		} else if strings.Contains(hLower, "letsnote") || strings.Contains(hLower, "let's note") || strings.Contains(hLower, "cf-s") || strings.Contains(hLower, "cf-f") {
			return "Panasonic Let's note"
		} else if strings.Contains(hLower, "lifebook") {
			return "Fujitsu LIFEBOOK"
		} else if strings.Contains(hLower, "dynabook") {
			return "Dynabook"
		} else if strings.Contains(hLower, "latitude") || strings.Contains(hLower, "optiplex") || strings.Contains(hLower, "xps") || strings.Contains(hLower, "dell") {
			return "Dell"
		} else if strings.Contains(hLower, "elitebook") || strings.Contains(hLower, "probook") || strings.Contains(hLower, "zbook") || strings.HasPrefix(hLower, "hp-") {
			return "HP"
		} else if strings.Contains(hLower, "vaio") {
			return "VAIO"
		}

		// Fallback for Windows OS with NIC vendor
		if strings.Contains(osVendor, "Windows") {
			return "Windows PC"
		} else if strings.Contains(osVendor, "macOS") {
			return "Apple Mac"
		} else if strings.Contains(osVendor, "Linux") {
			return "Linux Device"
		}
	}

	if currentVendor != "" && !isGenericVendor(currentVendor) {
		return currentVendor
	}

	return currentVendor
}

func isGenericVendor(vendor string) bool {
	v := strings.ToLower(strings.TrimSpace(vendor))
	return v == "" || v == "unknown" || v == "unknown vendor" || v == "network device"
}

