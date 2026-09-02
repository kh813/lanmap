package scanner

import (
	_ "embed"
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"sync"
)

//go:embed data/oui.csv
var ouiCSVData string

var (
	ouiMap  map[string]string
	ouiOnce sync.Once
)

func initOUIMap() {
	ouiOnce.Do(func() {
		ouiMap = make(map[string]string)
		reader := csv.NewReader(strings.NewReader(ouiCSVData))
		for {
			record, err := reader.Read()
			if err != nil {
				if err == io.EOF {
					break
				}
				continue
			}
			if len(record) >= 2 {
				prefix := strings.ToUpper(strings.TrimSpace(record[0]))
				vendor := strings.TrimSpace(record[1])
				if prefix != "" && vendor != "" {
					ouiMap[prefix] = vendor
				}
			}
		}
	})
}

// LookupVendor returns vendor name by MAC address, or checks for randomized MAC
func LookupVendor(mac string) string {
	initOUIMap()

	clean := strings.ToUpper(mac)
	clean = strings.ReplaceAll(clean, ":", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ReplaceAll(clean, ".", "")

	if len(clean) < 6 {
		return ""
	}

	prefix := clean[:6]
	if vendor, ok := ouiMap[prefix]; ok {
		return vendor
	}

	// Check if this is a Locally Administered Address (LAA / Randomized MAC)
	// In IEEE 802, bit 1 of byte 0 is 1 (e.g. first octet has 2nd hex digit as 2, 6, A, E)
	if isLocallyAdministeredMAC(clean) {
		return "端末 (プライベートMAC / Wi-Fi匿名化)"
	}

	return ""
}

func isLocallyAdministeredMAC(cleanMAC string) bool {
	if len(cleanMAC) < 2 {
		return false
	}
	firstByte, err := strconv.ParseUint(cleanMAC[:2], 16, 8)
	if err != nil {
		return false
	}
	// Bit 1 (0x02) indicates Locally Administered Address
	return (firstByte & 0x02) != 0
}
