package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"

	"corkboard/internal/model"
)

var validAccessLevels = map[string]bool{"invalid": true, "valid": true, "admin": true}

var validAccessProtocols = map[string]bool{
	"smb": true, "ldap": true, "mssql": true, "winrm": true,
	"rdp": true, "ssh": true, "other": true,
}

var validSecretTypes = map[string]bool{
	"password": true, "ntlm": true, "aes": true, "ssh_key": true,
	"ticket": true, "hash_uncracked": true, "other": true,
}

func ValidSecretType(t string) bool { return validSecretTypes[t] }

func ValidAccessLevel(l string) bool { return validAccessLevels[l] }

func ValidAccessProtocol(p string) bool { return validAccessProtocols[p] }

type CredInput struct {
	Domain     string
	Username   string
	Secret     string
	SecretType string
	Notes      string
	Access     []CredAccessInput
}

type CredAccessInput struct {
	IP       string
	Protocol string
	Level    string
}

func (s *Store) AddCred(ctx context.Context, actor string, c CredInput) (int64, error) {
	if c.Username == "" || c.Secret == "" {
		return 0, errors.New("username and secret are required")
	}
	if !validSecretTypes[c.SecretType] {
		return 0, errors.New("secret_type must be one of: password, ntlm, aes, ssh_key, ticket, hash_uncracked, other")
	}
	for _, a := range c.Access {
		if !validAccessLevels[a.Level] {
			return 0, fmt.Errorf("access level %q must be invalid, valid, or admin", a.Level)
		}
		if !validAccessProtocols[a.Protocol] {
			return 0, fmt.Errorf("access protocol %q is not a known protocol", a.Protocol)
		}
	}
	now := s.nowMS()
	var id int64
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT id FROM creds WHERE domain = ? AND username = ? AND secret = ? AND secret_type = ?`,
			c.Domain, c.Username, c.Secret, c.SecretType)
		if err := row.Scan(&id); err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			res, err := tx.ExecContext(ctx,
				`INSERT INTO creds (domain, username, secret, secret_type, source, notes, added_by, added_at)
				 VALUES (?, ?, ?, ?, 'manual', ?, ?, ?)`,
				c.Domain, c.Username, c.Secret, c.SecretType, c.Notes, actor, now)
			if err != nil {
				return err
			}
			id, err = res.LastInsertId()
			if err != nil {
				return err
			}
			if err := s.appendEvent(ctx, tx, now, actor, EventCredNew, nil, &id,
				fmt.Sprintf("new credential %s (manual)", model.CredName(c.Domain, c.Username)),
				jsonOr(map[string]int64{"cred_id": id})); err != nil {
				return err
			}
		}
		if err := ensureCredentialProfiles(ctx, tx); err != nil {
			return err
		}
		for _, a := range c.Access {
			hostID, err := s.upsertHostID(ctx, tx, a.IP, now)
			if err != nil {
				return err
			}
			if err := s.mergeAccessOneByID(ctx, tx, id, hostID, a.IP, a.Protocol, a.Level, "manual", now); err != nil {
				return err
			}
			if err := s.recordAccessObservation(ctx, tx, actor, id, hostID, a.Protocol, a.Level, "", "manual", nil, nil); err != nil {
				return err
			}

		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s *Store) AddCredAccess(ctx context.Context, actor string, credID int64, ip, protocol, level string) error {
	if !validAccessLevels[level] {
		return fmt.Errorf("level %q must be invalid, valid, or admin", level)
	}
	if !validAccessProtocols[protocol] {
		return fmt.Errorf("protocol %q is not a known protocol", protocol)
	}
	now := s.nowMS()
	var exists int
	if err := s.db.Read.QueryRowContext(ctx, `SELECT 1 FROM creds WHERE id = ?`, credID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownCred
		}
		return err
	}
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		hostID, err := s.upsertHostID(ctx, tx, ip, now)
		if err != nil {
			return err
		}
		if err := ensureCredentialProfiles(ctx, tx); err != nil {
			return err
		}
		if err := s.mergeAccessOneByID(ctx, tx, credID, hostID, ip, protocol, level, "manual", now); err != nil {
			return err
		}
		return s.recordAccessObservation(ctx, tx, actor, credID, hostID, protocol, level, "", "manual", nil, nil)
	})
}

func (s *Store) upsertHostID(ctx context.Context, tx *sql.Tx, ip string, now int64) (int64, error) {
	var hostID int64
	err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip = ?`, ip).Scan(&hostID)
	if errors.Is(err, sql.ErrNoRows) {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return 0, fmt.Errorf("host %q: %w", ip, err)
		}
		a16 := addr.As16()
		ipSort := a16[:]
		res, err := tx.ExecContext(ctx,
			`INSERT INTO hosts (ip, ip_sort, first_seen, last_seen, updated_at) VALUES (?, ?, ?, ?, ?)`,
			ip, ipSort, now, now, now)
		if err != nil {
			return 0, err
		}
		return res.LastInsertId()
	}
	if err != nil {
		return 0, err
	}
	return hostID, nil
}

func (s *Store) mergeAccessOne(ctx context.Context, tx *sql.Tx, credID int64, ip, protocol, level, source string, now int64) error {
	var hostID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip = ?`, ip).Scan(&hostID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("unknown host %s", ip)
		}
		return err
	}
	return s.mergeAccessOneByID(ctx, tx, credID, hostID, ip, protocol, level, source, now)
}

func (s *Store) mergeAccessOneByID(ctx context.Context, tx *sql.Tx, credID, hostID int64, ip, protocol, level, source string, now int64) error {
	newRank, ok := accessRank[level]
	if !ok {
		return fmt.Errorf("invalid access level %q", level)
	}
	var oldLevel string
	err := tx.QueryRowContext(ctx,
		`SELECT level FROM cred_access WHERE cred_id = ? AND host_id = ? AND protocol = ?`,
		credID, hostID, protocol).Scan(&oldLevel)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO cred_access (cred_id, host_id, protocol, level, source, observed_at)
			 VALUES (?, ?, ?, ?, ?, ?)`, credID, hostID, protocol, level, source, now); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		oldRank, _ := accessRank[oldLevel]
		if newRank > oldRank {
			if _, err := tx.ExecContext(ctx,
				`UPDATE cred_access SET level = ?, source = ?, observed_at = ?
				 WHERE cred_id = ? AND host_id = ? AND protocol = ?`,
				level, source, now, credID, hostID, protocol); err != nil {
				return err
			}
		}
	}
	if level == "admin" && oldLevel != "admin" {
		return s.appendEvent(ctx, tx, now, "system", EventCredAccessAdmin, &hostID, &credID,
			fmt.Sprintf("admin access as %s on %s (%s)", credNameTx(ctx, tx, credID), ip, protocol), "{}")
	}
	return nil
}

func (s *Store) ListCreds(ctx context.Context) ([]model.Cred, error) {
	rows, err := s.db.Read.QueryContext(ctx, `
		SELECT id, domain, username, secret, secret_type, source,
		       IFNULL(notes, ''), added_by, added_at
		FROM creds ORDER BY domain, username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Cred
	byID := map[int64]int{}
	for rows.Next() {
		var c model.Cred
		if err := rows.Scan(&c.ID, &c.Domain, &c.Username, &c.Secret, &c.SecretType,
			&c.Source, &c.Notes, &c.AddedBy, &c.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
		byID[c.ID] = len(out) - 1
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	arows, err := s.db.Read.QueryContext(ctx, `
		SELECT ca.cred_id, ca.host_id, h.ip, ca.protocol, ca.level, ca.observed_at
		FROM cred_access ca JOIN hosts h ON h.id = ca.host_id
		ORDER BY ca.cred_id, h.ip_sort, ca.protocol`)
	if err != nil {
		return nil, err
	}
	defer arows.Close()
	for arows.Next() {
		var a model.CredAccess
		var credID int64
		if err := arows.Scan(&credID, &a.HostID, &a.IP, &a.Protocol, &a.Level, &a.ObservedAt); err != nil {
			return nil, err
		}
		if idx, ok := byID[credID]; ok {
			out[idx].Access = append(out[idx].Access, a)
		}
	}
	return out, arows.Err()
}

func (s *Store) GetCred(ctx context.Context, id int64) (model.Cred, error) {
	var c model.Cred
	err := s.db.Read.QueryRowContext(ctx, `
		SELECT id, domain, username, secret, secret_type, source,
		       IFNULL(notes, ''), added_by, added_at
		FROM creds WHERE id = ?`, id).
		Scan(&c.ID, &c.Domain, &c.Username, &c.Secret, &c.SecretType,
			&c.Source, &c.Notes, &c.AddedBy, &c.AddedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrUnknownCred
	}
	if err != nil {
		return c, err
	}
	rows, err := s.db.Read.QueryContext(ctx, `
		SELECT ca.host_id, h.ip, ca.protocol, ca.level, ca.observed_at
		FROM cred_access ca JOIN hosts h ON h.id = ca.host_id
		WHERE ca.cred_id = ? ORDER BY h.ip_sort, ca.protocol`, id)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var a model.CredAccess
		if err := rows.Scan(&a.HostID, &a.IP, &a.Protocol, &a.Level, &a.ObservedAt); err != nil {
			return c, err
		}
		c.Access = append(c.Access, a)
	}
	return c, rows.Err()
}

type CredMatrix struct {
	Creds []model.Cred               `json:"creds"`
	Hosts []model.MatrixHost         `json:"hosts"`
	Cells map[int64]map[int64]string `json:"cells"`
}

func (s *Store) CredMatrix(ctx context.Context) (CredMatrix, error) {
	var m CredMatrix
	m.Cells = map[int64]map[int64]string{}

	crows, err := s.db.Read.QueryContext(ctx, `SELECT id FROM creds ORDER BY domain, username`)
	if err != nil {
		return m, err
	}
	var credIDs []int64
	for crows.Next() {
		var id int64
		if err := crows.Scan(&id); err != nil {
			crows.Close()
			return m, err
		}
		credIDs = append(credIDs, id)
	}
	if err := crows.Err(); err != nil {
		crows.Close()
		return m, err
	}
	crows.Close()
	if len(credIDs) == 0 {
		return m, nil
	}

	arows, err := s.db.Read.QueryContext(ctx, `
		SELECT ca.cred_id, ca.host_id, h.ip, ca.level
		FROM cred_access ca JOIN hosts h ON h.id = ca.host_id
		ORDER BY h.ip_sort, ca.cred_id`)
	if err != nil {
		return m, err
	}
	defer arows.Close()
	hostSeen := map[int64]bool{}
	levelRank := accessRank
	for arows.Next() {
		var credID, hostID int64
		var ip, level string
		if err := arows.Scan(&credID, &hostID, &ip, &level); err != nil {
			return m, err
		}
		if !hostSeen[hostID] {
			hostSeen[hostID] = true
			m.Hosts = append(m.Hosts, model.MatrixHost{ID: hostID, IP: ip})
		}
		if m.Cells[credID] == nil {
			m.Cells[credID] = map[int64]string{}
		}
		if cur, ok := m.Cells[credID][hostID]; !ok || levelRank[level] > levelRank[cur] {
			m.Cells[credID][hostID] = level
		}
	}
	if err := arows.Err(); err != nil {
		return m, err
	}
	creds, err := s.ListCreds(ctx)
	if err != nil {
		return m, err
	}
	m.Creds = creds
	return m, nil
}

func credNameTx(ctx context.Context, tx *sql.Tx, id int64) string {
	var domain, user string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(domain, ''), username FROM creds WHERE id = ?`, id).Scan(&domain, &user); err != nil {
		return fmt.Sprintf("cred %d", id)
	}
	return model.CredName(domain, user)
}
