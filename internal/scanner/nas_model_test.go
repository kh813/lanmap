package scanner

import (
	"testing"
)

func TestResolveNASModel(t *testing.T) {
	tests := []struct {
		name      string
		upnpModel string
		upnpName  string
		httpTitle string
		hostname  string
		vendor    string
		expected  string
	}{
		{
			name:      "Synology UPnP ModelName DS920+",
			upnpModel: "DS920+",
			upnpName:  "DiskStation",
			httpTitle: "Synology DSM",
			hostname:  "DiskStation",
			vendor:    "Synology Incorporated",
			expected:  "Synology DS920+",
		},
		{
			name:      "Synology UPnP ModelName DS218j with version",
			upnpModel: "DS218j",
			upnpName:  "DS218j (DS218j 6.2-24922)",
			httpTitle: "DiskStation - DSM",
			hostname:  "ds218j",
			vendor:    "Synology Incorporated",
			expected:  "Synology DS218J",
		},
		{
			name:      "Synology RS1221+ RackStation",
			upnpModel: "RS1221+",
			upnpName:  "RackStation",
			httpTitle: "RackStation - Synology DSM",
			hostname:  "rackstation",
			vendor:    "Synology Incorporated",
			expected:  "Synology RS1221+",
		},
		{
			name:      "Synology WebTitle only DS224+",
			upnpModel: "",
			upnpName:  "",
			httpTitle: "DS224+ - Synology DiskStation",
			hostname:  "nas",
			vendor:    "Synology",
			expected:  "Synology DS224+",
		},
		{
			name:      "QNAP UPnP TS-453D",
			upnpModel: "TS-453D",
			upnpName:  "NAS-QNAP",
			httpTitle: "QNAP Turbo NAS",
			hostname:  "qnap-453d",
			vendor:    "QNAP Systems, Inc.",
			expected:  "QNAP TS-453D",
		},
		{
			name:      "QNAP WebTitle TVS-h674",
			upnpModel: "",
			upnpName:  "",
			httpTitle: "TVS-h674 - QTS 5.1.0",
			hostname:  "qnap",
			vendor:    "QNAP Systems",
			expected:  "QNAP TVS-H674",
		},
		{
			name:      "I-O DATA LANDISK HDL2-AAX4",
			upnpModel: "HDL2-AAX4",
			upnpName:  "LANDISK-HDL2",
			httpTitle: "LANDISK Web Manager",
			hostname:  "landisk-01",
			vendor:    "I-O DATA DEVICE, INC.",
			expected:  "I-O DATA HDL2-AAX4",
		},
		{
			name:      "Buffalo TeraStation TS5410DN",
			upnpModel: "TS5410DN",
			upnpName:  "BUFFALO TeraStation",
			httpTitle: "TeraStation Settings",
			hostname:  "ts5410",
			vendor:    "BUFFALO INC.",
			expected:  "Buffalo TS5410DN",
		},
		{
			name:      "ASUSTOR AS5304T",
			upnpModel: "AS5304T",
			upnpName:  "ASUSTOR NAS",
			httpTitle: "ASUSTOR Data Master",
			hostname:  "asustor",
			vendor:    "ASUSTOR Inc.",
			expected:  "ASUSTOR AS5304T",
		},
		{
			name:      "TerraMaster F4-423",
			upnpModel: "F4-423",
			upnpName:  "TerraMaster TOS",
			httpTitle: "TerraMaster TOS",
			hostname:  "terramaster",
			vendor:    "TerraMaster",
			expected:  "TerraMaster F4-423",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveNASModel(tt.upnpModel, tt.upnpName, tt.httpTitle, tt.hostname, tt.vendor)
			if got != tt.expected {
				t.Errorf("ResolveNASModel() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestResolveMDNSModel_IgnoreNASVirtualIcons(t *testing.T) {
	// Virtual Apple Finder icon hints used by Synology/QNAP Avahi/Samba must NOT be resolved as real Apple models
	if res := ResolveMDNSModel("Xserve"); res != "" {
		t.Errorf("expected empty string for Xserve, got %q", res)
	}
	if res := ResolveMDNSModel("Xserver"); res != "" {
		t.Errorf("expected empty string for Xserver, got %q", res)
	}
	if res := ResolveMDNSModel("RackMac"); res != "" {
		t.Errorf("expected empty string for RackMac, got %q", res)
	}

	// Real Apple models must still resolve properly
	if res := ResolveMDNSModel("MacBookPro18,1"); res != "MacBook Pro (16-inch, 2021 M1 Pro)" {
		t.Errorf("expected MacBook Pro (16-inch, 2021 M1 Pro), got %q", res)
	}
}
