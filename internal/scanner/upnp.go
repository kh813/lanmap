package scanner

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// UPnPDeviceInfo contains extracted UPnP/SSDP device metadata
type UPnPDeviceInfo struct {
	FriendlyName string
	ModelName    string
	ModelNumber  string
	Manufacturer string
	SerialNumber string
}

type rootXML struct {
	Device struct {
		FriendlyName string `xml:"friendlyName"`
		Manufacturer string `xml:"manufacturer"`
		ModelName    string `xml:"modelName"`
		ModelNumber  string `xml:"modelNumber"`
		SerialNumber string `xml:"serialNumber"`
	} `xml:"device"`
}

// FetchUPnPInfo attempts to fetch UPnP/SSDP device description XML from common endpoints
func FetchUPnPInfo(ip string) *UPnPDeviceInfo {
	endpoints := []string{
		fmt.Sprintf("http://%s:8008/ssdp/device-desc.xml", ip), // Google Cast / Nest / Home
		fmt.Sprintf("http://%s:1900/rootDesc.xml", ip),
		fmt.Sprintf("http://%s:49152/description.xml", ip),
		fmt.Sprintf("http://%s:49153/description.xml", ip),
		fmt.Sprintf("http://%s:5000/rootDesc.xml", ip), // Synology
		fmt.Sprintf("http://%s:80/description.xml", ip),
	}

	client := &http.Client{
		Timeout: 350 * time.Millisecond,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	for _, url := range endpoints {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Close = true
		req.Header.Set("User-Agent", "lanmap/0.0.5")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 16384))
		resp.Body.Close()
		if err != nil || len(body) == 0 {
			continue
		}

		var root rootXML
		if err := xml.Unmarshal(body, &root); err == nil && (root.Device.FriendlyName != "" || root.Device.ModelName != "") {
			model := strings.TrimSpace(root.Device.ModelName)
			if root.Device.ModelNumber != "" {
				if model != "" {
					model = fmt.Sprintf("%s (%s)", model, strings.TrimSpace(root.Device.ModelNumber))
				} else {
					model = strings.TrimSpace(root.Device.ModelNumber)
				}
			}

			return &UPnPDeviceInfo{
				FriendlyName: strings.TrimSpace(root.Device.FriendlyName),
				ModelName:    model,
				ModelNumber:  strings.TrimSpace(root.Device.ModelNumber),
				Manufacturer: strings.TrimSpace(root.Device.Manufacturer),
				SerialNumber: strings.TrimSpace(root.Device.SerialNumber),
			}
		}
	}

	return nil
}
