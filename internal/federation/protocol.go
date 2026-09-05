package federation

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"lanmap/internal/db"
)

// CurrentSchemaVersion is the communication contract version
const CurrentSchemaVersion = 1

// PairStartResponse represents the response when server issues a 6-digit PIN
type PairStartResponse struct {
	PIN       string    `json:"pin"`
	ExpiresAt time.Time `json:"expires_at"`
	Message   string    `json:"message"`
}

// PairRequestPayload is sent by agent presenting a PIN
type PairRequestPayload struct {
	PIN     string `json:"pin"`
	Name    string `json:"name"`
	Version string `json:"version"`
	CIDR    string `json:"cidr"`
}

// PairRequestResponse is returned to agent upon receiving pairing request
type PairRequestResponse struct {
	AgentID string `json:"agent_id"`
	Status  string `json:"status"` // "requested"
	Message string `json:"message"`
}

// PairStatusResponse is returned during agent polling
type PairStatusResponse struct {
	Status string `json:"status"` // "issued", "requested", "approved", "rejected", "expired"
	Token  string `json:"token,omitempty"`
}

// PairApprovePayload is sent by Web UI admin to approve or reject
type PairApprovePayload struct {
	PIN string `json:"pin"`
}

// ReportPayload is sent periodically by the remote agent
type ReportPayload struct {
	AgentID       string    `json:"agent_id"`
	AgentName     string    `json:"agent_name"`
	AgentVersion  string    `json:"agent_version"`
	SchemaVersion int       `json:"schema_version"`
	CIDR          string    `json:"cidr"`
	ReportedAt    time.Time `json:"reported_at"`
	Hosts         []db.Host `json:"hosts"`
}

// ReportResponse is returned by server after ingesting remote hosts
type ReportResponse struct {
	Success         bool   `json:"success"`
	VersionMismatch bool   `json:"version_mismatch"`
	Message         string `json:"message"`
}

// ParseVersion splits a version string like "v0.0.16" into [major, minor, patch]
func ParseVersion(v string) (major, minor, patch int, err error) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return 0, 0, 0, fmt.Errorf("invalid version format: %s", v)
	}
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, err
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, 0, err
	}
	if len(parts) >= 3 {
		patchStr := strings.Split(parts[2], "-")[0] // strip -beta etc
		patch, _ = strconv.Atoi(patchStr)
	}
	return major, minor, patch, nil
}

// CheckVersionCompatibility evaluates if server and agent versions match or are incompatible
// If major version differs: incompatible (error returned)
// If minor/patch version differs: compatible but mismatch flag is true
func CheckVersionCompatibility(serverVer, agentVer string) (mismatch bool, err error) {
	sMaj, sMin, sPatch, sErr := ParseVersion(serverVer)
	aMaj, aMin, aPatch, aErr := ParseVersion(agentVer)

	if sErr != nil || aErr != nil {
		// Fallback to literal string compare
		return serverVer != agentVer, nil
	}

	if sMaj != aMaj {
		return true, fmt.Errorf("major version mismatch: server %s vs agent %s", serverVer, agentVer)
	}

	if sMin != aMin || sPatch != aPatch {
		return true, nil
	}

	return false, nil
}
