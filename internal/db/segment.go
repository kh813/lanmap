package db

import (
	"database/sql"
	"fmt"
	"net"
	"time"
)

// Segment represents a network segment
type Segment struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	CIDR          string    `json:"cidr"`
	InterfaceName string    `json:"interface_name"`
	IsEnabled     bool      `json:"is_enabled"`
	IsDefault     bool      `json:"is_default"`
	DHCPRange     string    `json:"dhcp_range"`
	CreatedAt     time.Time `json:"created_at"`
}

// CreateSegment creates a new network segment
func (db *DB) CreateSegment(name, cidr, iface string, isEnabled bool) (*Segment, error) {
	return db.CreateSegmentWithDHCP(name, cidr, iface, isEnabled, "")
}

// CreateSegmentWithDHCP creates a new network segment with optional DHCP IP range
func (db *DB) CreateSegmentWithDHCP(name, cidr, iface string, isEnabled bool, dhcpRange string) (*Segment, error) {
	if cidr != "" {
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR format: %w", err)
		}
	}

	res, err := db.Exec(
		"INSERT INTO segments (name, cidr, interface_name, is_enabled, is_default, dhcp_range) VALUES (?, ?, ?, ?, 0, ?)",
		name, cidr, iface, isEnabled, dhcpRange,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert segment: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return db.GetSegment(id)
}

// GetSegment retrieves a segment by ID
func (db *DB) GetSegment(id int64) (*Segment, error) {
	row := db.QueryRow("SELECT id, name, cidr, interface_name, is_enabled, is_default, dhcp_range, created_at FROM segments WHERE id = ?", id)
	var s Segment
	var iface, dhcpRange sql.NullString
	err := row.Scan(&s.ID, &s.Name, &s.CIDR, &iface, &s.IsEnabled, &s.IsDefault, &dhcpRange, &s.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	s.InterfaceName = iface.String
	s.DHCPRange = dhcpRange.String
	return &s, nil
}

// GetDefaultSegment retrieves the default (Uncategorized) segment
func (db *DB) GetDefaultSegment() (*Segment, error) {
	row := db.QueryRow("SELECT id, name, cidr, interface_name, is_enabled, is_default, dhcp_range, created_at FROM segments WHERE is_default = 1 LIMIT 1")
	var s Segment
	var iface, dhcpRange sql.NullString
	err := row.Scan(&s.ID, &s.Name, &s.CIDR, &iface, &s.IsEnabled, &s.IsDefault, &dhcpRange, &s.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	s.InterfaceName = iface.String
	s.DHCPRange = dhcpRange.String
	return &s, nil
}

// ListSegments returns all segments
func (db *DB) ListSegments() ([]*Segment, error) {
	rows, err := db.Query("SELECT id, name, cidr, interface_name, is_enabled, is_default, dhcp_range, created_at FROM segments ORDER BY is_default DESC, id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*Segment
	for rows.Next() {
		var s Segment
		var iface, dhcpRange sql.NullString
		if err := rows.Scan(&s.ID, &s.Name, &s.CIDR, &iface, &s.IsEnabled, &s.IsDefault, &dhcpRange, &s.CreatedAt); err != nil {
			return nil, err
		}
		s.InterfaceName = iface.String
		s.DHCPRange = dhcpRange.String
		list = append(list, &s)
	}
	return list, rows.Err()
}

// UpdateSegment updates an existing segment
func (db *DB) UpdateSegment(s *Segment) error {
	if s.CIDR != "" {
		_, _, err := net.ParseCIDR(s.CIDR)
		if err != nil {
			return fmt.Errorf("invalid CIDR format: %w", err)
		}
	}

	_, err := db.Exec(
		"UPDATE segments SET name = ?, cidr = ?, interface_name = ?, is_enabled = ?, dhcp_range = ? WHERE id = ?",
		s.Name, s.CIDR, s.InterfaceName, s.IsEnabled, s.DHCPRange, s.ID,
	)
	return err
}

// DeleteSegment deletes a segment by ID (fails if segment is default)
func (db *DB) DeleteSegment(id int64) error {
	seg, err := db.GetSegment(id)
	if err != nil {
		return err
	}
	if seg == nil {
		return fmt.Errorf("segment not found")
	}
	if seg.IsDefault {
		return fmt.Errorf("cannot delete default segment")
	}

	_, err = db.Exec("DELETE FROM segments WHERE id = ?", id)
	return err
}

// CheckCIDROverlap checks if the given CIDR overlaps with any existing enabled segments
func (db *DB) CheckCIDROverlap(cidrStr string, excludeID int64) ([]*Segment, error) {
	if cidrStr == "" {
		return nil, nil
	}
	_, targetNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	segments, err := db.ListSegments()
	if err != nil {
		return nil, err
	}

	var overlapping []*Segment
	for _, seg := range segments {
		if seg.ID == excludeID || !seg.IsEnabled || seg.CIDR == "" {
			continue
		}
		_, segNet, err := net.ParseCIDR(seg.CIDR)
		if err != nil {
			continue
		}

		// Two subnets overlap if one contains the other's network address or broadcast/last address
		if targetNet.Contains(segNet.IP) || segNet.Contains(targetNet.IP) {
			overlapping = append(overlapping, seg)
		}
	}
	return overlapping, nil
}

// FindSegmentForIP finds the most specific matching enabled segment for an IP address
func (db *DB) FindSegmentForIP(ip net.IP) (*Segment, error) {
	segments, err := db.ListSegments()
	if err != nil {
		return nil, err
	}

	var bestSeg *Segment
	var bestMaskSize int = -1

	for _, seg := range segments {
		if !seg.IsEnabled || seg.CIDR == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(seg.CIDR)
		if err != nil {
			continue
		}

		if ipNet.Contains(ip) {
			ones, _ := ipNet.Mask.Size()
			if ones > bestMaskSize {
				bestMaskSize = ones
				bestSeg = seg
			}
		}
	}

	if bestSeg != nil {
		return bestSeg, nil
	}

	return db.GetDefaultSegment()
}
