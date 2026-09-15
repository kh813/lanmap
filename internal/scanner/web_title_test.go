package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func TestInferModelFromWebResponse(t *testing.T) {
	tests := []struct {
		name          string
		title         string
		body          string
		serverHdr     string
		currentVendor string
		expectedModel string
	}{
		{
			name:          "Netgear WAX610 in Title",
			title:         "NETGEAR WAX610",
			body:          "<html><body>Welcome</body></html>",
			serverHdr:     "",
			currentVendor: "Netgear",
			expectedModel: "NETGEAR WAX610",
		},
		{
			name:          "Netgear GS108Tv3 Switch",
			title:         "GS108Tv3 - Smart Managed Plus Switch",
			body:          "<html><body>NETGEAR Smart Switch Login</body></html>",
			serverHdr:     "",
			currentVendor: "",
			expectedModel: "NETGEAR GS108Tv3",
		},
		{
			name:          "Netgear Orbi RBK752",
			title:         "Orbi RBK752 Router",
			body:          "NETGEAR Orbi System",
			serverHdr:     "",
			currentVendor: "Netgear Inc.",
			expectedModel: "NETGEAR RBK752",
		},
		{
			name:          "Yamaha RTX830 Router",
			title:         "RTX830 Web GUI",
			body:          "<html><body>Yamaha Network OS</body></html>",
			serverHdr:     "",
			currentVendor: "Yamaha Corporation",
			expectedModel: "Yamaha RTX830",
		},
		{
			name:          "Yamaha WLX212 Wireless AP",
			title:         "WLX212 Web GUI",
			body:          "Yamaha Wireless Access Point",
			serverHdr:     "",
			currentVendor: "Yamaha",
			expectedModel: "Yamaha WLX212",
		},
		{
			name:          "Fortinet FortiGate-60F",
			title:         "FortiGate-60F",
			body:          "<html><body>Fortinet Login</body></html>",
			serverHdr:     "",
			currentVendor: "Fortinet Inc.",
			expectedModel: "Fortinet FortiGate-60F",
		},
		{
			name:          "Buffalo WAPM-1266R Access Point",
			title:         "WAPM-1266R 設定画面",
			body:          "BUFFALO AirStation Pro",
			serverHdr:     "",
			currentVendor: "BUFFALO INC.",
			expectedModel: "Buffalo WAPM-1266R",
		},
		{
			name:          "Cisco Meraki MR36",
			title:         "Meraki MR36 Setup",
			body:          "Cisco Meraki Cloud Managed AP",
			serverHdr:     "",
			currentVendor: "Cisco Systems",
			expectedModel: "Cisco Meraki MR36",
		},
		{
			name:          "Aruba Instant On AP22",
			title:         "Instant On AP22 WebUI",
			body:          "Aruba Instant On",
			serverHdr:     "",
			currentVendor: "Hewlett Packard Enterprise",
			expectedModel: "Aruba Instant On AP22",
		},
		{
			name:          "Mist Systems AP43",
			title:         "Mist AP43 Login",
			body:          "Juniper Mist Access Point",
			serverHdr:     "",
			currentVendor: "Juniper Networks",
			expectedModel: "Mist Systems AP43",
		},
		{
			name:          "TP-Link EAP610",
			title:         "EAP610 - Omada Access Point",
			body:          "TP-Link Omada Controller",
			serverHdr:     "",
			currentVendor: "TP-Link",
			expectedModel: "TP-Link EAP610",
		},
		{
			name:          "Allied Telesis AT-GS950",
			title:         "AT-GS950/8 Web Management",
			body:          "Allied Telesis CentreCOM",
			serverHdr:     "",
			currentVendor: "Allied Telesis",
			expectedModel: "Allied Telesis AT-GS950/8",
		},
		{
			name:          "Synology DiskStation DS920+",
			title:         "Synology DiskStation - DS920+",
			body:          "DSM 7.2",
			serverHdr:     "nginx",
			currentVendor: "Synology",
			expectedModel: "Synology DS920+",
		},
		{
			name:          "QNAP TS-453D",
			title:         "QNAP Turbo NAS (TS-453D)",
			body:          "QTS 5.0",
			serverHdr:     "",
			currentVendor: "QNAP Systems",
			expectedModel: "QNAP TS-453D",
		},
		{
			name:          "i-PRO Security Camera WV-S1131",
			title:         "i-PRO WV-S1131 Network Camera",
			body:          "i-PRO Camera System",
			serverHdr:     "",
			currentVendor: "i-PRO",
			expectedModel: "i-PRO WV-S1131",
		},
		{
			name:          "Axis Camera AXIS M3065-V",
			title:         "AXIS M3065-V Network Camera",
			body:          "Axis Communications",
			serverHdr:     "",
			currentVendor: "Axis Communications",
			expectedModel: "AXIS M3065-V",
		},
		{
			name:          "Hikvision Camera DS-2CD2143G2-I",
			title:         "DS-2CD2143G2-I Web Management",
			body:          "Hikvision Web Camera",
			serverHdr:     "",
			currentVendor: "Hikvision",
			expectedModel: "Hikvision DS-2CD2143G2-I",
		},
		{
			name:          "Yealink IP Phone SIP-T46U",
			title:         "Yealink SIP-T46U Phone",
			body:          "Yealink IP Phone",
			serverHdr:     "",
			currentVendor: "Yealink",
			expectedModel: "Yealink SIP-T46U",
		},
		{
			name:          "Grandstream IP Phone GRP2614",
			title:         "Grandstream GRP2614",
			body:          "Grandstream Networks",
			serverHdr:     "",
			currentVendor: "Grandstream",
			expectedModel: "Grandstream GRP2614",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := InferModelFromWebResponse(tc.title, tc.body, tc.serverHdr, tc.currentVendor)
			if got != tc.expectedModel {
				t.Errorf("InferModelFromWebResponse() = %q, want %q", got, tc.expectedModel)
			}
		})
	}
}

func TestEnrichVendorWithModel(t *testing.T) {
	tests := []struct {
		currentVendor string
		inferredModel string
		expected      string
	}{
		{"", "NETGEAR WAX610", "NETGEAR WAX610"},
		{"Unknown", "Yamaha RTX830", "Yamaha RTX830"},
		{"Netgear", "NETGEAR WAX610", "NETGEAR WAX610"},
		{"Yamaha Corporation", "Yamaha RTX830", "Yamaha RTX830"},
		{"Fortinet Inc.", "Fortinet FortiGate-60F", "Fortinet FortiGate-60F"},
		{"BUFFALO INC.", "Buffalo WAPM-1266R", "Buffalo WAPM-1266R"},
		{"Apple", "", "Apple"},
	}

	for _, tc := range tests {
		got := EnrichVendorWithModel(tc.currentVendor, tc.inferredModel)
		if got != tc.expected {
			t.Errorf("EnrichVendorWithModel(%q, %q) = %q, want %q", tc.currentVendor, tc.inferredModel, got, tc.expected)
		}
	}
}

func TestExtractWebTitleAndModel_Server(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>NETGEAR WAX610 Access Point</title></head><body>Login</body></html>"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse test server url: %v", err)
	}

	portStr := u.Port()
	port, _ := strconv.Atoi(portStr)

	title, model := ExtractWebTitleAndModel(u.Hostname(), fmt.Sprintf("%d:HTTP", port), "Netgear")
	if title != "NETGEAR WAX610 Access Point" {
		t.Errorf("expected title 'NETGEAR WAX610 Access Point', got %q", title)
	}
	if model != "NETGEAR WAX610" {
		t.Errorf("expected model 'NETGEAR WAX610', got %q", model)
	}
}
