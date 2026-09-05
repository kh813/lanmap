package scanner

import (
	"testing"
)

func TestNormalizeMAC_IPv6(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"b6:e:5f:59:b7:64", "b6:0e:5f:59:b7:64"},
		{"38:97:a4:4f:84:60", "38:97:a4:4f:84:60"},
		{"0-11-22-33-44-55", "00:11:22:33:44:55"},
		{"00:11:22:33:44:55", "00:11:22:33:44:55"},
		{"(incomplete)", "(incomplete)"},
	}

	for _, tc := range tests {
		got := NormalizeMAC(tc.input)
		if got != tc.want {
			t.Errorf("NormalizeMAC(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseNDPOutput(t *testing.T) {
	sample := `Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs
240b:10:2060:e500:850:ef4e:8c61:e83d    (incomplete)         en0 expired   N      
240b:10:2060:e500:18a3:1e01:c1ba:80c2   8a:22:c1:5c:85:f7    en0 17h38m25s S      
240b:10:2060:e500:3a97:a4ff:fe4f:8461   38:97:a4:4f:84:60    en0 5m58s     R      
fe80::422:f4b1:b412:2280%en0            b6:e:5f:59:b7:64     en0 permanent R      
fe80::3a97:a4ff:fe4f:8460%en0           38:97:a4:4f:84:60    en0 2m17s     R  R   
`
	entries := ParseNDPOutput(sample)
	if len(entries) != 4 {
		t.Fatalf("expected 4 valid entries, got %d", len(entries))
	}

	// Entry 1: GUA, Stale
	if entries[0].IP != "240b:10:2060:e500:18a3:1e01:c1ba:80c2" || entries[0].MAC != "8a:22:c1:5c:85:f7" || entries[0].IsRouter {
		t.Errorf("unexpected entry 0: %+v", entries[0])
	}

	// Entry 2: GUA, Reachable
	if entries[1].IP != "240b:10:2060:e500:3a97:a4ff:fe4f:8461" || entries[1].MAC != "38:97:a4:4f:84:60" {
		t.Errorf("unexpected entry 1: %+v", entries[1])
	}

	// Entry 3: LLA, padded MAC b6:0e:...
	if entries[2].IP != "fe80::422:f4b1:b412:2280" || entries[2].MAC != "b6:0e:5f:59:b7:64" {
		t.Errorf("unexpected entry 2: %+v", entries[2])
	}

	// Entry 4: LLA, Router flag 'R'
	if entries[3].IP != "fe80::3a97:a4ff:fe4f:8460" || entries[3].MAC != "38:97:a4:4f:84:60" || !entries[3].IsRouter {
		t.Errorf("unexpected entry 3 (router expected): %+v", entries[3])
	}
}

func TestParseIPNeighOutput(t *testing.T) {
	sample := `fe80::211:22ff:fe33:4455 dev eth0 lladdr 00:11:22:33:44:55 router REACHABLE
2001:db8::50 dev eth0 lladdr 00:11:22:33:44:55 STALE
fe80::1 dev eth0 FAILED
`
	entries := ParseIPNeighOutput(sample)
	if len(entries) != 2 {
		t.Fatalf("expected 2 valid entries, got %d", len(entries))
	}

	if entries[0].IP != "fe80::211:22ff:fe33:4455" || !entries[0].IsRouter || entries[0].Interface != "eth0" {
		t.Errorf("unexpected entry 0: %+v", entries[0])
	}
	if entries[1].IP != "2001:db8::50" || entries[1].IsRouter {
		t.Errorf("unexpected entry 1: %+v", entries[1])
	}
}

func TestParseWindowsNeighOutput(t *testing.T) {
	sample := `Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
fe80::1                                       00-11-22-33-44-55  Reachable
fe80::99                                      00-aa-bb-cc-dd-ee  Unreachable
`
	entries := ParseWindowsNeighOutput(sample)
	if len(entries) != 1 {
		t.Fatalf("expected 1 valid entry, got %d", len(entries))
	}
	if entries[0].IP != "fe80::1" || entries[0].MAC != "00:11:22:33:44:55" {
		t.Errorf("unexpected entry 0: %+v", entries[0])
	}
}
