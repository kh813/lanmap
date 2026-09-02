package db

import (
	"database/sql"
	"encoding/csv"
	"io"
	"strings"
	"time"
)

// WhitelistEntry represents a pre-registered allowed device from asset ledger
type WhitelistEntry struct {
	ID           int64     `json:"id"`
	Hostname     string    `json:"hostname"`
	MACAddress   string    `json:"mac_address"`
	SerialNumber string    `json:"serial_number"`
	DeviceName   string    `json:"device_name"`
	Note         string    `json:"note"`
	CreatedAt    time.Time `json:"created_at"`
}

// AddWhitelistEntry adds a single whitelist entry
func (db *DB) AddWhitelistEntry(e *WhitelistEntry) error {
	normMAC := strings.ToLower(strings.TrimSpace(e.MACAddress))
	cleanHost := strings.TrimSpace(e.Hostname)

	query := `
	INSERT INTO whitelist_entries (hostname, mac_address, serial_number, device_name, note)
	VALUES (?, ?, ?, ?, ?)
	`
	res, err := db.Exec(query, cleanHost, normMAC, strings.TrimSpace(e.SerialNumber), strings.TrimSpace(e.DeviceName), strings.TrimSpace(e.Note))
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err == nil {
		e.ID = id
	}
	return nil
}

// ImportWhitelistCSV imports multiple whitelist records from CSV/TSV content
func (db *DB) ImportWhitelistCSV(content string) (int, error) {
	reader := csv.NewReader(strings.NewReader(content))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1 // flexible column count

	// Check if TSV
	if strings.Contains(content, "\t") && !strings.Contains(content, ",") {
		reader.Comma = '\t'
	}

	imported := 0
	isHeader := true

	for {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		if len(record) == 0 {
			continue
		}

		// Detect and skip header row
		firstCol := strings.ToLower(strings.TrimSpace(record[0]))
		if isHeader && (firstCol == "hostname" || firstCol == "host" || firstCol == "ホスト名" || firstCol == "pc名" || firstCol == "ip" || firstCol == "mac") {
			isHeader = false
			continue
		}
		isHeader = false

		hostname := strings.TrimSpace(record[0])
		var mac, serial, devName, note string

		if len(record) > 1 {
			mac = strings.TrimSpace(record[1])
		}
		if len(record) > 2 {
			serial = strings.TrimSpace(record[2])
		}
		if len(record) > 3 {
			devName = strings.TrimSpace(record[3])
		}
		if len(record) > 4 {
			note = strings.TrimSpace(record[4])
		}

		if hostname == "" && mac == "" {
			continue
		}

		entry := &WhitelistEntry{
			Hostname:     hostname,
			MACAddress:   mac,
			SerialNumber: serial,
			DeviceName:   devName,
			Note:         note,
		}

		if err := db.AddWhitelistEntry(entry); err == nil {
			imported++
		}
	}

	return imported, nil
}

// ListWhitelistEntries retrieves all whitelist entries
func (db *DB) ListWhitelistEntries() ([]*WhitelistEntry, error) {
	rows, err := db.Query("SELECT id, hostname, mac_address, serial_number, device_name, note, created_at FROM whitelist_entries ORDER BY id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*WhitelistEntry
	for rows.Next() {
		var e WhitelistEntry
		var host, mac, serial, name, note sql.NullString
		if err := rows.Scan(&e.ID, &host, &mac, &serial, &name, &note, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Hostname = host.String
		e.MACAddress = mac.String
		e.SerialNumber = serial.String
		e.DeviceName = name.String
		e.Note = note.String
		list = append(list, &e)
	}

	return list, rows.Err()
}

// DeleteWhitelistEntry deletes an entry by ID
func (db *DB) DeleteWhitelistEntry(id int64) error {
	_, err := db.Exec("DELETE FROM whitelist_entries WHERE id = ?", id)
	return err
}

// ClearWhitelistEntries removes all whitelist entries
func (db *DB) ClearWhitelistEntries() error {
	_, err := db.Exec("DELETE FROM whitelist_entries")
	return err
}

// MatchWhitelist checks if a host matches any entry in the whitelist
func (db *DB) MatchWhitelist(hostname, macAddress string) (*WhitelistEntry, bool) {
	cleanHost := strings.ToLower(strings.TrimSpace(hostname))
	cleanMAC := strings.ToLower(strings.TrimSpace(macAddress))

	entries, err := db.ListWhitelistEntries()
	if err != nil || len(entries) == 0 {
		return nil, false
	}

	// 1. First priority: MAC Address Match
	if cleanMAC != "" {
		for _, e := range entries {
			if e.MACAddress != "" && strings.EqualFold(e.MACAddress, cleanMAC) {
				return e, true
			}
		}
	}

	// 2. Second priority: Hostname Match (exact or prefix without domain)
	if cleanHost != "" {
		baseHost := strings.Split(cleanHost, ".")[0]
		for _, e := range entries {
			if e.Hostname == "" {
				continue
			}
			wlHost := strings.ToLower(strings.TrimSpace(e.Hostname))
			wlBase := strings.Split(wlHost, ".")[0]

			if cleanHost == wlHost || baseHost == wlBase || strings.EqualFold(cleanHost, wlHost) || strings.EqualFold(baseHost, wlBase) {
				return e, true
			}
		}
	}

	return nil, false
}

// ReconcileHostsWithWhitelist reconciles all unapproved hosts against the whitelist
func (db *DB) ReconcileHostsWithWhitelist() (int, error) {
	hosts, err := db.ListHosts(nil, false)
	if err != nil {
		return 0, err
	}

	updated := 0
	for _, h := range hosts {
		if h.IsApproved {
			continue
		}

		if match, ok := db.MatchWhitelist(h.Hostname, h.MACAddress); ok {
			dispName := h.DisplayName
			if dispName == "" && match.DeviceName != "" {
				dispName = match.DeviceName
			} else if dispName == "" && match.Hostname != "" {
				dispName = match.Hostname
			}

			_, err := db.Exec("UPDATE hosts SET is_approved = 1, display_name = ? WHERE ip = ?", dispName, h.IP)
			if err == nil {
				updated++
			}
		}
	}

	return updated, nil
}
