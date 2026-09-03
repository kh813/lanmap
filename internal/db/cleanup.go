package db

import (
	"fmt"
)

// CleanupOldHosts deletes hosts that haven't been seen for retentionDays,
// respecting the protection conditions: is_protected=1, is_static_ip=1, is_approved=1.
// If retentionDays <= 0, cleanup is disabled.
func (db *DB) CleanupOldHosts(retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}

	query := `
	DELETE FROM hosts
	WHERE (
		(last_seen IS NOT NULL AND last_seen < datetime('now', '-' || ? || ' days'))
		OR (last_seen IS NULL AND first_seen < datetime('now', '-' || ? || ' days'))
	)
	AND is_protected = 0
	AND is_static_ip = 0
	AND is_approved = 0
	`

	res, err := db.Exec(query, retentionDays, retentionDays)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old hosts: %w", err)
	}

	return res.RowsAffected()
}
