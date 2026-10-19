package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"corkboard/internal/model"
)

type CompromiseRow struct {
	model.Compromise
	CredUser     string `json:"via_cred_user,omitempty"`
	FindingTitle string `json:"via_finding_title,omitempty"`
}

func (s *Store) ListCompromises(ctx context.Context) ([]CompromiseRow, error) {
	rows, err := s.db.Read.QueryContext(ctx, `
		SELECT c.id, c.host_id, h.ip, c.level, c.via_finding_id, c.via_cred_id,
		       IFNULL(c.via_text, ''), c.by_user, c.at,
		       IFNULL(cu.dom, ''), IFNULL(cu.un, ''),
		       IFNULL(f.title, '')
		FROM compromises c
		JOIN hosts h ON h.id = c.host_id
		LEFT JOIN (
			SELECT id, IFNULL(domain, '') AS dom, username AS un
			FROM creds
		) cu ON cu.id = c.via_cred_id
		LEFT JOIN findings f ON f.id = c.via_finding_id
		ORDER BY c.at, c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CompromiseRow
	for rows.Next() {
		var r CompromiseRow
		var dom, un string
		if err := rows.Scan(&r.ID, &r.HostID, &r.IP, &r.Level, &r.ViaFindingID,
			&r.ViaCredID, &r.ViaText, &r.ByUser, &r.At, &dom, &un, &r.FindingTitle); err != nil {
			return nil, err
		}
		if un != "" {
			r.CredUser = un
			if dom != "" {
				r.CredUser = dom + `\` + un
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type ExportHost struct {
	model.Host
	HostnameList []string `json:"-"`
}

func (s *Store) ListExportHosts(ctx context.Context) ([]ExportHost, error) {
	rows, err := s.db.Read.QueryContext(ctx, `
		SELECT h.id, h.ip, IFNULL(h.os, ''), h.os_accuracy, IFNULL(h.domain, ''),
		       IFNULL(h.mac, ''), IFNULL(h.mac_vendor, ''), h.status, h.scope_zone,
		       IFNULL(h.owner, ''), h.claimed_at, h.priority, h.first_seen,
		       h.last_seen, h.updated_at,
		       (SELECT IFNULL(GROUP_CONCAT(name, ','), '') FROM hostnames hn WHERE hn.host_id = h.id)
		FROM hosts h ORDER BY h.ip_sort, h.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExportHost
	for rows.Next() {
		var h ExportHost
		var osAcc sql.NullInt64
		var claimed sql.NullInt64
		var hostnames string
		if err := rows.Scan(&h.ID, &h.IP, &h.OS, &osAcc, &h.Domain, &h.MAC,
			&h.MACVendor, &h.Status, &h.Zone, &h.Owner, &claimed, &h.Priority,
			&h.FirstSeen, &h.LastSeen, &h.UpdatedAt, &hostnames); err != nil {
			return nil, err
		}
		if osAcc.Valid {
			v := int(osAcc.Int64)
			h.OSAccuracy = &v
		}
		if claimed.Valid {
			h.ClaimedAt = claimed.Int64
		}
		if hostnames != "" {
			h.HostnameList = strings.Split(hostnames, ",")
			h.Hostnames = make([]model.Hostname, len(h.HostnameList))
			for i, n := range h.HostnameList {
				h.Hostnames[i] = model.Hostname{Name: n}
			}
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

type OpenPortSummary struct {
	IP    string
	Proto string
	Port  int
	Name  string
}

func (s *Store) ListOpenServices(ctx context.Context) ([]OpenPortSummary, error) {
	rows, err := s.db.Read.QueryContext(ctx, `
		SELECT h.ip, sv.proto, sv.port, IFNULL(sv.name, '')
		FROM services sv JOIN hosts h ON h.id = sv.host_id
		WHERE sv.state = 'open'
		ORDER BY h.ip_sort, sv.port, sv.proto`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OpenPortSummary
	for rows.Next() {
		var p OpenPortSummary
		var name string
		if err := rows.Scan(&p.IP, &p.Proto, &p.Port, &name); err != nil {
			return nil, err
		}
		p.Name = name
		out = append(out, p)
	}
	return out, rows.Err()
}

type ServiceCSV struct {
	IP      string
	Proto   string
	Port    int
	State   string
	Name    string
	Product string
	Version string
}

func (s *Store) ListServicesCSV(ctx context.Context) ([]ServiceCSV, error) {
	rows, err := s.db.Read.QueryContext(ctx, `
		SELECT h.ip, sv.proto, sv.port, sv.state, IFNULL(sv.name, ''), IFNULL(sv.product, ''), IFNULL(sv.version, '')
		FROM services sv JOIN hosts h ON h.id = sv.host_id
		ORDER BY h.ip_sort, sv.port, sv.proto, sv.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceCSV
	for rows.Next() {
		var r ServiceCSV
		var name, product, version string
		if err := rows.Scan(&r.IP, &r.Proto, &r.Port, &r.State, &name, &product, &version); err != nil {
			return nil, err
		}
		r.Name, r.Product, r.Version = name, product, version
		out = append(out, r)
	}
	return out, rows.Err()
}

type FindingCSV struct {
	ID       int64
	Title    string
	Severity string
	Source   string
	State    string
	Hosts    string
}

func (s *Store) ListFindingsCSV(ctx context.Context) ([]FindingCSV, error) {
	rows, err := s.db.Read.QueryContext(ctx, `
		SELECT f.id, f.title, f.severity, f.source, f.state,
		       (SELECT IFNULL(GROUP_CONCAT(h.ip, ','), '')
		          FROM finding_hosts fh JOIN hosts h ON h.id = fh.host_id
		          WHERE fh.finding_id = f.id
		          ORDER BY h.ip_sort)
		FROM findings f WHERE f.merged_into IS NULL ORDER BY f.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingCSV
	for rows.Next() {
		var r FindingCSV
		var hosts string
		if err := rows.Scan(&r.ID, &r.Title, &r.Severity, &r.Source, &r.State, &hosts); err != nil {
			return nil, err
		}
		r.Hosts = hosts
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) ListNotes(ctx context.Context) ([]model.Note, error) {
	rows, err := s.db.Read.QueryContext(ctx, `
		SELECT id, host_id, author, body, created_at
		FROM notes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Note
	for rows.Next() {
		var n model.Note
		if err := rows.Scan(&n.ID, &n.HostID, &n.Author, &n.Body, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

type CredAccessSummary struct {
	CredID  int64
	ValidOn []string
	AdminOn []string
}

func (s *Store) CredAccessSummaries(ctx context.Context) ([]CredAccessSummary, error) {
	rows, err := s.db.Read.QueryContext(ctx, `
		SELECT ca.cred_id, h.ip, ca.level
		FROM cred_access ca JOIN hosts h ON h.id = ca.host_id
		ORDER BY ca.cred_id, h.ip_sort`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byID := map[int64]*CredAccessSummary{}
	var order []int64
	var out []CredAccessSummary
	for rows.Next() {
		var cid int64
		var ip, level string
		if err := rows.Scan(&cid, &ip, &level); err != nil {
			return nil, err
		}
		su, ok := byID[cid]
		if !ok {
			su = &CredAccessSummary{CredID: cid}
			byID[cid] = su
			order = append(order, cid)
		}
		switch level {
		case "admin":
			su.AdminOn = append(su.AdminOn, ip)
		case "valid":
			su.ValidOn = append(su.ValidOn, ip)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}

func SubnetKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "other"
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.Is4() {
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.0/24", b[0], b[1], b[2])
	}
	var b [8]byte
	a16 := addr.As16()
	copy(b[:], a16[:8])
	return fmt.Sprintf("%x:%x:%x:%x::/64", uint16(b[0])<<8|uint16(b[1]), uint16(b[2])<<8|uint16(b[3]), uint16(b[4])<<8|uint16(b[5]), uint16(b[6])<<8|uint16(b[7]))
}

func (s *Store) LogExportReveal(ctx context.Context, actor string) error {
	now := s.nowMS()
	return s.appendEvent(ctx, s.db.Write, now, actor, EventCredReveal, nil, nil,
		fmt.Sprintf("%s exported credentials with reveal=1", actor), "{}")
}

var ErrNoCreds = errors.New("no credentials")
