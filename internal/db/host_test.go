package db

import (
	"strings"
	"testing"
)

func TestHost_VendorModelClassification(t *testing.T) {
	tests := []struct {
		name          string
		vendorModel   string
		mdnsModel     string
		upnpModel     string
		isHardware    bool
		isRandomMAC   bool
		isVM          bool
		expectedClass string
	}{
		{
			name:          "MacBook Pro verified model",
			vendorModel:   "MacBook Pro (14-inch, M5, 2025)",
			mdnsModel:     "MacBook Pro (14-inch, M5, 2025)",
			isHardware:    true,
			isRandomMAC:   false,
			isVM:          false,
			expectedClass: "text-slate-900 dark:text-slate-100 font-medium",
		},
		{
			name:          "Lenovo ThinkPad X1 Carbon",
			vendorModel:   "Lenovo ThinkPad X1 Carbon Gen 12",
			isHardware:    true,
			isRandomMAC:   false,
			isVM:          false,
			expectedClass: "text-slate-900 dark:text-slate-100 font-medium",
		},
		{
			name:          "Synology NAS model",
			vendorModel:   "Synology DS920+",
			isHardware:    true,
			isRandomMAC:   false,
			isVM:          false,
			expectedClass: "text-slate-900 dark:text-slate-100 font-medium",
		},
		{
			name:          "Yamaha Router",
			vendorModel:   "Yamaha RTX830",
			isHardware:    true,
			isRandomMAC:   false,
			isVM:          false,
			expectedClass: "text-slate-900 dark:text-slate-100 font-medium",
		},
		{
			name:          "Intel NIC Chip Vendor only",
			vendorModel:   "Intel Corporate",
			isHardware:    false,
			isRandomMAC:   false,
			isVM:          false,
			expectedClass: "text-slate-400 dark:text-slate-500",
		},
		{
			name:          "Realtek NIC Chip Vendor only",
			vendorModel:   "Realtek Semiconductor Corp.",
			isHardware:    false,
			isRandomMAC:   false,
			isVM:          false,
			expectedClass: "text-slate-400 dark:text-slate-500",
		},
		{
			name:          "AzureWave NIC Chip Vendor only",
			vendorModel:   "AzureWave Technology Inc.",
			isHardware:    false,
			isRandomMAC:   false,
			isVM:          false,
			expectedClass: "text-slate-400 dark:text-slate-500",
		},
		{
			name:          "Private MAC / Wi-Fi randomized",
			vendorModel:   "端末 (プライベートMAC / Wi-Fi匿名化)",
			isHardware:    false,
			isRandomMAC:   true,
			isVM:          false,
			expectedClass: "text-slate-400 dark:text-slate-500 italic",
		},
		{
			name:          "Virtual Machine (VMware)",
			vendorModel:   "VMware ESXi / vSphere (仮想マシン)",
			isHardware:    false,
			isRandomMAC:   false,
			isVM:          true,
			expectedClass: "text-purple-600 dark:text-purple-400",
		},
		{
			name:          "Legacy Xserve icon artifact in VendorModel",
			vendorModel:   "Model: Xserve",
			mdnsModel:     "Model: Xserve",
			isHardware:    false,
			isRandomMAC:   false,
			isVM:          false,
			expectedClass: "text-slate-400 dark:text-slate-500",
		},
		{
			name:          "Corrupted Xserve artifact in VendorModel",
			vendorModel:   "Model:Xserve5",
			mdnsModel:     "",
			isHardware:    false,
			isRandomMAC:   false,
			isVM:          false,
			expectedClass: "text-slate-400 dark:text-slate-500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Host{
				VendorModel: tt.vendorModel,
				MDNSModel:   tt.mdnsModel,
				UPnPModel:   tt.upnpModel,
			}

			if got := h.IsHardwareModel(); got != tt.isHardware {
				t.Errorf("IsHardwareModel() = %v, want %v", got, tt.isHardware)
			}
			if got := h.IsRandomMAC(); got != tt.isRandomMAC {
				t.Errorf("IsRandomMAC() = %v, want %v", got, tt.isRandomMAC)
			}
			if got := h.IsVirtualMachine(); got != tt.isVM {
				t.Errorf("IsVirtualMachine() = %v, want %v", got, tt.isVM)
			}
			if got := h.VendorModelClass(); got != tt.expectedClass {
				if !strings.Contains(got, tt.expectedClass) {
					t.Errorf("VendorModelClass() = %q, want %q", got, tt.expectedClass)
				}
			}
		})
	}
}
