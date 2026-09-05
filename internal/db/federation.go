package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// FederationAgent represents a remote site lanmap agent
type FederationAgent struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	TokenHash       string     `json:"-"`
	RemoteIP        string     `json:"remote_ip"`
	CIDR            string     `json:"cidr"`
	Status          string     `json:"status"` // "active", "pending", "revoked"
	Version         string     `json:"version"`
	SchemaVersion   int        `json:"schema_version"`
	VersionMismatch bool       `json:"version_mismatch"`
	LastSeenAt      *time.Time `json:"last_seen_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	HostCount       int        `json:"host_count"`
	OnlineHostCount int        `json:"online_host_count"`
}

// FederationPairingPIN represents a one-time pairing PIN request
type FederationPairingPIN struct {
	PIN          string    `json:"pin"`
	AgentID      string    `json:"agent_id"`
	AgentName    string    `json:"agent_name"`
	AgentVersion string    `json:"agent_version"`
	AgentCIDR    string    `json:"agent_cidr"`
	RemoteIP     string    `json:"remote_ip"`
	Status       string    `json:"status"` // "issued", "requested", "approved", "rejected", "expired"
	Token        string    `json:"token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// HashToken returns SHA-256 hex digest of the given bearer token
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// GenerateSecureToken generates a cryptographically secure 32-byte hex token
func GenerateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GeneratePIN generates a 6-digit numeric PIN
func GeneratePIN() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()+100000), nil
}

// CreatePairingPIN generates and stores a new 6-digit PIN valid for 15 minutes
func (db *DB) CreatePairingPIN(agentName string) (*FederationPairingPIN, error) {
	pin, err := GeneratePIN()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PIN: %w", err)
	}

	expiresAt := time.Now().Add(15 * time.Minute)
	query := `
	INSERT INTO federation_pairing_pins (pin, agent_name, status, expires_at, created_at)
	VALUES (?, ?, 'issued', ?, CURRENT_TIMESTAMP)
	`
	_, err = db.Exec(query, pin, agentName, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to insert pairing PIN: %w", err)
	}

	return &FederationPairingPIN{
		PIN:       pin,
		AgentName: agentName,
		Status:    "issued",
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}, nil
}

// RequestPairing is called by a remote agent presenting a PIN to request pairing
func (db *DB) RequestPairing(pin, agentName, agentVersion, agentCIDR, remoteIP string) (agentID string, err error) {
	pin = strings.TrimSpace(pin)
	var status string
	var expiresAt time.Time

	row := db.QueryRow("SELECT status, expires_at FROM federation_pairing_pins WHERE pin = ?", pin)
	if err := row.Scan(&status, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("invalid PIN")
		}
		return "", err
	}

	if time.Now().After(expiresAt) {
		_, _ = db.Exec("UPDATE federation_pairing_pins SET status = 'expired' WHERE pin = ?", pin)
		return "", fmt.Errorf("PIN has expired")
	}

	if status != "issued" && status != "requested" {
		return "", fmt.Errorf("PIN is not in a valid state: %s", status)
	}

	// Generate agent UUID
	agentUUIDBytes := make([]byte, 16)
	if _, err := rand.Read(agentUUIDBytes); err != nil {
		return "", err
	}
	agentID = fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		agentUUIDBytes[0:4],
		agentUUIDBytes[4:6],
		agentUUIDBytes[6:8],
		agentUUIDBytes[8:10],
		agentUUIDBytes[10:16],
	)

	updateQuery := `
	UPDATE federation_pairing_pins
	SET agent_id = ?, agent_name = ?, agent_version = ?, agent_cidr = ?, remote_ip = ?, status = 'requested'
	WHERE pin = ?
	`
	_, err = db.Exec(updateQuery, agentID, agentName, agentVersion, agentCIDR, remoteIP, pin)
	if err != nil {
		return "", fmt.Errorf("failed to update pairing PIN request: %w", err)
	}

	return agentID, nil
}

// GetPairingStatus is polled by the agent (3-5 minutes) to check if admin approved
func (db *DB) GetPairingStatus(pin, agentID string) (status string, token string, err error) {
	var expiresAt time.Time
	var tok sql.NullString
	row := db.QueryRow("SELECT status, token, expires_at FROM federation_pairing_pins WHERE pin = ? AND (agent_id = ? OR agent_id IS NULL)", pin, agentID)
	if err := row.Scan(&status, &tok, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return "not_found", "", nil
		}
		return "", "", err
	}

	if time.Now().After(expiresAt) && status != "approved" {
		return "expired", "", nil
	}

	if tok.Valid {
		token = tok.String
	}
	return status, token, nil
}

// ListPendingPairingRequests returns all PINs with status='requested' that haven't expired
func (db *DB) ListPendingPairingRequests() ([]FederationPairingPIN, error) {
	query := `
	SELECT pin, agent_id, agent_name, agent_version, agent_cidr, remote_ip, status, expires_at, created_at
	FROM federation_pairing_pins
	WHERE status = 'requested' AND expires_at > CURRENT_TIMESTAMP
	ORDER BY created_at DESC
	`
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []FederationPairingPIN
	for rows.Next() {
		var p FederationPairingPIN
		var agentID, name, ver, cidr, rip sql.NullString
		if err := rows.Scan(&p.PIN, &agentID, &name, &ver, &cidr, &rip, &p.Status, &p.ExpiresAt, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.AgentID = agentID.String
		p.AgentName = name.String
		p.AgentVersion = ver.String
		p.AgentCIDR = cidr.String
		p.RemoteIP = rip.String
		list = append(list, p)
	}
	return list, nil
}

// ApprovePairing is called by admin from Web UI. It creates the agent and stores the token
func (db *DB) ApprovePairing(pin string) (token string, err error) {
	var agentID, agentName, agentVersion, agentCIDR, remoteIP, status string
	var expiresAt time.Time

	row := db.QueryRow("SELECT agent_id, agent_name, agent_version, agent_cidr, remote_ip, status, expires_at FROM federation_pairing_pins WHERE pin = ?", pin)
	if err := row.Scan(&agentID, &agentName, &agentVersion, &agentCIDR, &remoteIP, &status, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("pairing request not found")
		}
		return "", err
	}

	if status != "requested" {
		return "", fmt.Errorf("pairing request is not in 'requested' state: %s", status)
	}

	token, err = GenerateSecureToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate agent token: %w", err)
	}
	tokenHash := HashToken(token)

	// Insert or replace into federation_agents
	agentQuery := `
	INSERT INTO federation_agents (
		id, name, token_hash, remote_ip, cidr, status, version, schema_version, version_mismatch, last_seen_at, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, 'active', ?, 1, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	ON CONFLICT(id) DO UPDATE SET
		name = excluded.name,
		token_hash = excluded.token_hash,
		remote_ip = excluded.remote_ip,
		cidr = excluded.cidr,
		status = 'active',
		version = excluded.version,
		updated_at = CURRENT_TIMESTAMP
	`
	if _, err := db.Exec(agentQuery, agentID, agentName, tokenHash, remoteIP, agentCIDR, agentVersion); err != nil {
		return "", fmt.Errorf("failed to register agent: %w", err)
	}

	// Update pin status to approved and store token for polling pickup
	_, err = db.Exec("UPDATE federation_pairing_pins SET status = 'approved', token = ? WHERE pin = ?", token, pin)
	if err != nil {
		return "", fmt.Errorf("failed to update pin to approved: %w", err)
	}

	return token, nil
}

// RejectPairing marks the pairing request as rejected
func (db *DB) RejectPairing(pin string) error {
	_, err := db.Exec("UPDATE federation_pairing_pins SET status = 'rejected' WHERE pin = ?", pin)
	return err
}

// ListAgents returns all registered federation agents with host counts
func (db *DB) ListAgents() ([]FederationAgent, error) {
	query := `
	SELECT
		a.id, a.name, a.remote_ip, a.cidr, a.status, a.version,
		a.schema_version, a.version_mismatch, a.last_seen_at, a.created_at, a.updated_at,
		COUNT(h.id) as host_count,
		COALESCE(SUM(CASE WHEN h.status = 'up' THEN 1 ELSE 0 END), 0) as online_host_count
	FROM federation_agents a
	LEFT JOIN hosts h ON h.agent_id = a.id
	GROUP BY a.id
	ORDER BY a.name ASC
	`
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []FederationAgent
	for rows.Next() {
		var a FederationAgent
		var lastSeen sql.NullTime
		var cidr sql.NullString
		if err := rows.Scan(
			&a.ID, &a.Name, &a.RemoteIP, &cidr, &a.Status, &a.Version,
			&a.SchemaVersion, &a.VersionMismatch, &lastSeen, &a.CreatedAt, &a.UpdatedAt,
			&a.HostCount, &a.OnlineHostCount,
		); err != nil {
			return nil, err
		}
		if lastSeen.Valid {
			a.LastSeenAt = &lastSeen.Time
		}
		a.CIDR = cidr.String
		agents = append(agents, a)
	}
	return agents, nil
}

// GetAgentByID fetches an agent by UUID
func (db *DB) GetAgentByID(id string) (*FederationAgent, error) {
	query := `
	SELECT
		id, name, token_hash, remote_ip, cidr, status, version,
		schema_version, version_mismatch, last_seen_at, created_at, updated_at
	FROM federation_agents
	WHERE id = ?
	`
	row := db.QueryRow(query, id)
	var a FederationAgent
	var lastSeen sql.NullTime
	var cidr sql.NullString
	err := row.Scan(
		&a.ID, &a.Name, &a.TokenHash, &a.RemoteIP, &cidr, &a.Status, &a.Version,
		&a.SchemaVersion, &a.VersionMismatch, &lastSeen, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if lastSeen.Valid {
		a.LastSeenAt = &lastSeen.Time
	}
	a.CIDR = cidr.String
	return &a, nil
}

// GetAgentByTokenHash fetches an active agent by SHA-256 token hash
func (db *DB) GetAgentByTokenHash(tokenHash string) (*FederationAgent, error) {
	query := `
	SELECT
		id, name, token_hash, remote_ip, cidr, status, version,
		schema_version, version_mismatch, last_seen_at, created_at, updated_at
	FROM federation_agents
	WHERE token_hash = ? AND status = 'active'
	`
	row := db.QueryRow(query, tokenHash)
	var a FederationAgent
	var lastSeen sql.NullTime
	var cidr sql.NullString
	err := row.Scan(
		&a.ID, &a.Name, &a.TokenHash, &a.RemoteIP, &cidr, &a.Status, &a.Version,
		&a.SchemaVersion, &a.VersionMismatch, &lastSeen, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if lastSeen.Valid {
		a.LastSeenAt = &lastSeen.Time
	}
	a.CIDR = cidr.String
	return &a, nil
}

// UpdateAgentHeartbeat updates last_seen, IP, version, and mismatch status
func (db *DB) UpdateAgentHeartbeat(id string, remoteIP, version string, schemaVersion int, versionMismatch bool) error {
	query := `
	UPDATE federation_agents
	SET remote_ip = ?, version = ?, schema_version = ?, version_mismatch = ?, last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?
	`
	_, err := db.Exec(query, remoteIP, version, schemaVersion, versionMismatch, id)
	return err
}

// RevokeAgent invalidates the agent's active status
func (db *DB) RevokeAgent(id string) error {
	query := "UPDATE federation_agents SET status = 'revoked', updated_at = CURRENT_TIMESTAMP WHERE id = ?"
	_, err := db.Exec(query, id)
	return err
}

// DeleteAgent removes the agent and all its associated remote hosts
func (db *DB) DeleteAgent(id string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM hosts WHERE agent_id = ?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM federation_agents WHERE id = ?", id); err != nil {
		return err
	}
	return tx.Commit()
}

// UpsertRemoteHosts updates or inserts hosts reported by a remote agent
// Complete isolation: hosts belonging to different agent_id (or NULL for server) never conflict even with identical private IPs
func (db *DB) UpsertRemoteHosts(agentID string, hosts []Host) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	upsertSQL := `
	INSERT INTO hosts (
		ip, agent_id, mac_address, hostname, vendor_model, display_name,
		os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
		open_ports, http_title, upnp_name, upnp_model, upnp_serial,
		tls_subject, tls_expiry, mdns_model,
		is_approved, is_protected, is_static_ip, is_dhcp,
		is_monitored, is_paused, has_conflict,
		first_seen, last_seen
	) VALUES (
		?, ?, ?, ?, ?, ?,
		?, ?, ?, ?, ?,
		?, ?, ?, ?, ?,
		?, ?, ?,
		?, ?, ?, ?,
		?, ?, ?,
		COALESCE(?, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP
	)
	ON CONFLICT(id) DO NOTHING
	`

	for _, h := range hosts {
		if strings.TrimSpace(h.IP) == "" {
			continue
		}

		// Find existing host in DB for this agent_id and IP
		var existingID int64
		var currentMAC sql.NullString
		row := tx.QueryRow("SELECT id, mac_address FROM hosts WHERE agent_id = ? AND ip = ? ORDER BY id DESC LIMIT 1", agentID, h.IP)
		err := row.Scan(&existingID, &currentMAC)

		if err == sql.ErrNoRows {
			// Insert new host scoped to agent_id
			_, err = tx.Exec(upsertSQL,
				h.IP, agentID, h.MACAddress, h.Hostname, h.VendorModel, h.DisplayName,
				h.OSVendor, h.Status, h.PingRTTMs, h.PingJitterMs, h.UptimePct,
				h.OpenPorts, h.HTTPTitle, h.UPnPName, h.UPnPModel, h.UPnPSerial,
				h.TLSSubject, h.TLSExpiry, h.MDNSModel,
				h.IsApproved, h.IsProtected, h.IsStaticIP, h.IsDHCP,
				h.IsMonitored, h.IsPaused, h.HasConflict,
				h.FirstSeen,
			)
			if err != nil {
				return fmt.Errorf("failed to insert remote host %s: %w", h.IP, err)
			}
		} else if err != nil {
			return err
		} else {
			// Check if MAC changed (device replacement on same IP)
			if h.MACAddress != "" && currentMAC.Valid && currentMAC.String != "" &&
				!strings.EqualFold(strings.TrimSpace(h.MACAddress), strings.TrimSpace(currentMAC.String)) {
				// Mark previous as superseded/offline
				_, _ = tx.Exec("UPDATE hosts SET status = 'down' WHERE id = ?", existingID)
				// Insert new row for the new MAC
				_, err = tx.Exec(upsertSQL,
					h.IP, agentID, h.MACAddress, h.Hostname, h.VendorModel, h.DisplayName,
					h.OSVendor, h.Status, h.PingRTTMs, h.PingJitterMs, h.UptimePct,
					h.OpenPorts, h.HTTPTitle, h.UPnPName, h.UPnPModel, h.UPnPSerial,
					h.TLSSubject, h.TLSExpiry, h.MDNSModel,
					h.IsApproved, h.IsProtected, h.IsStaticIP, h.IsDHCP,
					h.IsMonitored, h.IsPaused, h.HasConflict,
					time.Now(),
				)
				if err != nil {
					return fmt.Errorf("failed to replace remote host %s: %w", h.IP, err)
				}
			} else {
				// Update existing host
				updateSQL := `
				UPDATE hosts SET
					mac_address = COALESCE(NULLIF(?, ''), mac_address),
					hostname = COALESCE(NULLIF(?, ''), hostname),
					vendor_model = COALESCE(NULLIF(?, ''), vendor_model),
					display_name = CASE WHEN display_name IS NULL OR display_name = '' THEN ? ELSE display_name END,
					os_vendor = COALESCE(NULLIF(?, ''), os_vendor),
					status = ?,
					ping_rtt_ms = COALESCE(?, ping_rtt_ms),
					ping_jitter_ms = COALESCE(?, ping_jitter_ms),
					uptime_pct = ?,
					open_ports = ?,
					http_title = ?,
					upnp_name = ?,
					upnp_model = ?,
					upnp_serial = ?,
					tls_subject = ?,
					tls_expiry = ?,
					mdns_model = ?,
					is_dhcp = ?,
					last_seen = CURRENT_TIMESTAMP
				WHERE id = ?
				`
				_, err = tx.Exec(updateSQL,
					h.MACAddress, h.Hostname, h.VendorModel, h.DisplayName, h.OSVendor,
					h.Status, h.PingRTTMs, h.PingJitterMs, h.UptimePct,
					h.OpenPorts, h.HTTPTitle, h.UPnPName, h.UPnPModel, h.UPnPSerial,
					h.TLSSubject, h.TLSExpiry, h.MDNSModel, h.IsDHCP,
					existingID,
				)
				if err != nil {
					return fmt.Errorf("failed to update remote host %s (id=%d): %w", h.IP, existingID, err)
				}
			}
		}
	}

	return tx.Commit()
}
