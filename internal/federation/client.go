package federation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"lanmap/internal/db"
)

// AgentConfig holds local federation pairing configuration
type AgentConfig struct {
	ServerURL string `json:"server_url"`
	Token     string `json:"token"`
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
}

// IsPaired returns true if agent has a configured server URL and token
func (c *AgentConfig) IsPaired() bool {
	return c != nil && c.ServerURL != "" && c.Token != ""
}

// LoadAgentConfig reads federation agent configuration from local settings table
func LoadAgentConfig(database *db.DB) (*AgentConfig, error) {
	serverURL, _ := database.GetSetting("agent_server_url")
	token, _ := database.GetSetting("agent_token")
	agentID, _ := database.GetSetting("agent_id")
	agentName, _ := database.GetSetting("agent_name")

	if serverURL == "" || token == "" {
		return &AgentConfig{
			ServerURL: serverURL,
			Token:     token,
			AgentID:   agentID,
			AgentName: agentName,
		}, nil
	}

	return &AgentConfig{
		ServerURL: serverURL,
		Token:     token,
		AgentID:   agentID,
		AgentName: agentName,
	}, nil
}

// SaveAgentConfig saves federation agent configuration to local settings table
func SaveAgentConfig(database *db.DB, cfg *AgentConfig) error {
	if err := database.SetSetting("agent_server_url", cfg.ServerURL); err != nil {
		return err
	}
	if err := database.SetSetting("agent_token", cfg.Token); err != nil {
		return err
	}
	if err := database.SetSetting("agent_id", cfg.AgentID); err != nil {
		return err
	}
	return database.SetSetting("agent_name", cfg.AgentName)
}

// ClearAgentConfig clears federation configuration from local database
func ClearAgentConfig(database *db.DB) error {
	_ = database.SetSetting("agent_server_url", "")
	_ = database.SetSetting("agent_token", "")
	_ = database.SetSetting("agent_id", "")
	_ = database.SetSetting("agent_name", "")
	return nil
}

var customHTTPClient *http.Client

// SetCustomHTTPClient sets a custom HTTP client (useful for mock or in-process testing)
func SetCustomHTTPClient(c *http.Client) {
	customHTTPClient = c
}

// GetHTTPClient returns the active HTTP client
func GetHTTPClient() *http.Client {
	if customHTTPClient != nil {
		return customHTTPClient
	}
	return NewHTTPClient()
}

// NewHTTPClient creates an HTTP client with sensible timeout and Mesh-VPN TLS support
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Allow self-signed TLS certificates in internal Mesh-VPN (Tailscale/custom)
			},
		},
	}
}

// Pair executes the full 2-stage pairing sequence against the server
func Pair(ctx context.Context, serverURL, pin, name, version, cidr string, onWaiting func(agentID string)) (*AgentConfig, error) {
	serverURL = strings.TrimRight(serverURL, "/")
	client := GetHTTPClient()

	reqPayload := PairRequestPayload{
		PIN:     pin,
		Name:    name,
		Version: version,
		CIDR:    cidr,
	}
	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, err
	}

	// 1. Send pairing request
	req, err := http.NewRequestWithContext(ctx, "POST", serverURL+"/api/federation/pair/request", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server %s: %w", serverURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("pairing request failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var pairResp PairRequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&pairResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if onWaiting != nil {
		onWaiting(pairResp.AgentID)
	}

	// 2. Poll for approval (up to 3 minutes or until context cancelled)
	pollTicker := time.NewTicker(3 * time.Second)
	defer pollTicker.Stop()

	timeout := time.After(3 * time.Minute)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return nil, fmt.Errorf("pairing timed out after 3 minutes without server approval")
		case <-pollTicker.C:
			statusURL := fmt.Sprintf("%s/api/federation/pair/status?pin=%s&agent_id=%s", serverURL, pin, pairResp.AgentID)
			statusReq, err := http.NewRequestWithContext(ctx, "GET", statusURL, nil)
			if err != nil {
				continue
			}

			sResp, err := client.Do(statusReq)
			if err != nil {
				continue
			}

			var stat PairStatusResponse
			_ = json.NewDecoder(sResp.Body).Decode(&stat)
			sResp.Body.Close()

			switch stat.Status {
			case "approved":
				if stat.Token == "" {
					return nil, fmt.Errorf("received approval but token was empty")
				}
				return &AgentConfig{
					ServerURL: serverURL,
					Token:     stat.Token,
					AgentID:   pairResp.AgentID,
					AgentName: name,
				}, nil
			case "rejected":
				return nil, fmt.Errorf("pairing request was rejected by server administrator")
			case "expired":
				return nil, fmt.Errorf("pairing PIN has expired")
			case "not_found":
				return nil, fmt.Errorf("pairing request was cancelled or not found")
			}
		}
	}
}

// PushReport sends the local network inventory to the central lanmap server
func PushReport(ctx context.Context, serverURL, token string, payload ReportPayload) (*ReportResponse, error) {
	serverURL = strings.TrimRight(serverURL, "/")
	client := GetHTTPClient()

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", serverURL+"/api/federation/report", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Lanmap-Agent-Version", payload.AgentVersion)
	req.Header.Set("X-Lanmap-Schema-Version", fmt.Sprintf("%d", payload.SchemaVersion))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send report: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("report submission failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var repResp ReportResponse
	if err := json.NewDecoder(resp.Body).Decode(&repResp); err != nil {
		return nil, fmt.Errorf("failed to decode report response: %w", err)
	}

	return &repResp, nil
}
