package scanner

import (
	_ "embed"
	"encoding/csv"
	"io"
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

// LookupVendor returns vendor name by MAC address, or "Unknown Vendor"
func LookupVendor(mac string) string {
	initOUIMap()

	// Normalize MAC: strip separators (: - .) and take first 6 hex characters
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

	return ""
}
