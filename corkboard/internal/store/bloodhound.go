package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"corkboard/internal/model"
)

type BloodHoundTarget struct {
	ID           int64  `json:"id"`
	Kind         string `json:"kind"`
	Identity     string `json:"identity"`
	HostID       *int64 `json:"host_id,omitempty"`
	IP           string `json:"ip,omitempty"`
	State        string `json:"state"`
	Error        string `json:"error,omitempty"`
	ObjectID     string `json:"object_id,omitempty"`
	ResolvedName string `json:"resolved_name,omitempty"`
	UpdatedAt    int64  `json:"updated_at"`
	SyncedAt     int64  `json:"synced_at"`
}

var bloodHoundSID = regexp.MustCompile(`(?i)^S-1-[0-9]+(?:-[0-9]+)+$`)

func bloodHoundIdentity(kind, identity string) (string, error) {
	if len(identity) > 512 || strings.IndexFunc(identity, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("%w: identity must be at most 512 bytes without control characters", ErrInvalidInput)
	}
	identity = strings.TrimSpace(identity)
	if kind != "Computer" && kind != "User" {
		return "", fmt.Errorf("%w: kind must be Computer or User", ErrInvalidInput)
	}
	if bloodHoundSID.MatchString(identity) {
		return identity, nil
	}
	if kind == "Computer" {
		identity = strings.TrimSuffix(identity, ".")
		if validDirectoryDomain(identity, true) {
			return identity, nil
		}
	} else if strings.Count(identity, "@") == 1 {
		user, domain, _ := strings.Cut(identity, "@")
		if user != "" && user == strings.TrimSpace(user) && !strings.ContainsAny(user, `\/`) && validDirectoryDomain(domain, false) {
			return identity, nil
		}
	}
	return "", fmt.Errorf("%w: use a Computer FQDN, User USER@DOMAIN, or full SID", ErrInvalidInput)
}

func validDirectoryDomain(name string, requireDot bool) bool {
	if len(name) == 0 || len(name) > 253 || (requireDot && !strings.Contains(name, ".")) {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

const bloodHoundTargetColumns = `b.id, b.kind, b.identity, b.host_id, COALESCE(h.ip, ''),
	b.state, b.error, b.object_id, b.resolved_name, b.updated_at, b.synced_at`

func scanBloodHoundTarget(row taskScanner) (BloodHoundTarget, error) {
	var target BloodHoundTarget
	var hostID sql.NullInt64
	err := row.Scan(&target.ID, &target.Kind, &target.Identity, &hostID, &target.IP,
		&target.State, &target.Error, &target.ObjectID, &target.ResolvedName, &target.UpdatedAt, &target.SyncedAt)
	if hostID.Valid {
		target.HostID = &hostID.Int64
	}
	return target, err
}

func (s *Store) SaveBloodHoundTarget(ctx context.Context, actor, kind, identity string, hostID *int64) (BloodHoundTarget, error) {
	var target BloodHoundTarget
	identity, err := bloodHoundIdentity(kind, identity)
	if err != nil {
		return target, err
	}
	if kind == "Computer" && hostID == nil || kind == "User" && hostID != nil {
		return target, fmt.Errorf("%w: Computers require a host; Users must not reference a host", ErrInvalidInput)
	}
	err = s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var err error
		target, err = s.saveBloodHoundTarget(ctx, tx, actor, kind, identity, hostID)
		return err
	})
	return target, err
}

func (s *Store) saveBloodHoundTarget(ctx context.Context, tx *sql.Tx, actor, kind, identity string, hostID *int64) (BloodHoundTarget, error) {
	var target BloodHoundTarget
	if hostID != nil {
		var status, zone string
		if err := tx.QueryRowContext(ctx, `SELECT status, scope_zone FROM hosts WHERE id = ?`, *hostID).Scan(&status, &zone); errors.Is(err, sql.ErrNoRows) {
			return target, ErrUnknownHost
		} else if err != nil {
			return target, err
		}
		if status != "compromised" || zone != "in" && zone != "caution" {
			return target, fmt.Errorf("%w: computer mapping requires a compromised host in scope", ErrInvalidInput)
		}
	}
	where, arg := "b.kind = 'User' AND b.identity = ? COLLATE NOCASE", any(identity)
	if hostID != nil {
		where, arg = "b.kind = 'Computer' AND b.host_id = ?", *hostID
	}
	old, err := scanBloodHoundTarget(tx.QueryRowContext(ctx, `SELECT `+bloodHoundTargetColumns+
		` FROM bloodhound_targets b LEFT JOIN hosts h ON h.id = b.host_id WHERE `+where, arg))
	if err == nil && strings.EqualFold(old.Identity, identity) {
		return old, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return target, err
	}
	now := s.nowMS()
	var id int64
	if err == nil {
		id = old.ID
		_, err = tx.ExecContext(ctx, `UPDATE bloodhound_targets SET identity = ?, state = 'pending', error = '',
			object_id = '', resolved_name = '', updated_at = ?, synced_at = 0 WHERE id = ?`, identity, now, id)
	} else {
		var res sql.Result
		res, err = tx.ExecContext(ctx, `INSERT INTO bloodhound_targets (kind, identity, host_id, updated_at)
			VALUES (?, ?, ?, ?)`, kind, identity, hostID, now)
		if err == nil {
			id, err = res.LastInsertId()
		}
	}
	if err != nil {
		return target, err
	}
	if err := s.appendEvent(ctx, tx, now, actor, EventBloodHoundTarget, hostID, &id,
		fmt.Sprintf("%s mapped BloodHound %s %s", actor, kind, identity), "{}"); err != nil {
		return target, err
	}
	return scanBloodHoundTarget(tx.QueryRowContext(ctx, `SELECT `+bloodHoundTargetColumns+
		` FROM bloodhound_targets b LEFT JOIN hosts h ON h.id = b.host_id WHERE b.id = ?`, id))
}

func (s *Store) ListBloodHoundTargets(ctx context.Context) ([]BloodHoundTarget, error) {
	rows, err := s.db.Read.QueryContext(ctx, `SELECT `+bloodHoundTargetColumns+
		` FROM bloodhound_targets b LEFT JOIN hosts h ON h.id = b.host_id ORDER BY b.kind, b.identity, b.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	targets := make([]BloodHoundTarget, 0)
	for rows.Next() {
		target, err := scanBloodHoundTarget(rows)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (s *Store) QueueBloodHoundTargets(ctx context.Context) error {
	_, err := s.db.Write.ExecContext(ctx, `UPDATE bloodhound_targets SET state = 'pending', error = '', updated_at = ?
		WHERE kind = 'User' OR host_id IN (SELECT id FROM hosts WHERE status = 'compromised' AND scope_zone IN ('in', 'caution'))`, s.nowMS())
	return err
}

func (s *Store) FinishBloodHoundTarget(ctx context.Context, id int64, identity, objectID, resolvedName, errorText string) error {
	if len(objectID) > 512 || len(resolvedName) > 512 || strings.IndexFunc(objectID+resolvedName, unicode.IsControl) >= 0 {
		return fmt.Errorf("%w: invalid resolved BloodHound object", ErrInvalidInput)
	}
	errorText = strings.TrimSpace(strings.ReplaceAll(errorText, "\x00", ""))
	if len(errorText) > 2048 {
		errorText = strings.ToValidUTF8(errorText[:2048], "")
	}
	state, syncedAt := "synced", s.nowMS()
	if errorText != "" {
		state, syncedAt = "error", 0
	}
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var hostID sql.NullInt64
		var kind string
		err := tx.QueryRowContext(ctx, `SELECT kind, host_id FROM bloodhound_targets WHERE id = ? AND identity = ? COLLATE NOCASE`, id, identity).Scan(&kind, &hostID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE bloodhound_targets SET state = ?, error = ?, object_id = ?,
			resolved_name = ?, updated_at = ?, synced_at = ? WHERE id = ?`, state, errorText, objectID, resolvedName, s.nowMS(), syncedAt, id); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, s.nowMS(), "system", EventBloodHoundSync, nullablePtr64(&hostID), &id,
			fmt.Sprintf("BloodHound %s %s: %s", kind, identity, state), "{}")
	})
}

func (s *Store) PrepareBloodHoundTargets(ctx context.Context) error {
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT h.id, hn.name, hn.source FROM hosts h
			JOIN hostnames hn ON hn.host_id = h.id
			WHERE h.status = 'compromised' AND h.scope_zone IN ('in', 'caution')
			AND NOT EXISTS (SELECT 1 FROM bloodhound_targets b WHERE b.host_id = h.id)
			ORDER BY h.id, hn.name`)
		if err != nil {
			return err
		}
		byHost := make(map[int64][]model.Hostname)
		for rows.Next() {
			var id int64
			var name, source string
			if err := rows.Scan(&id, &name, &source); err != nil {
				rows.Close()
				return err
			}
			byHost[id] = append(byHost[id], model.Hostname{Name: name, Source: source})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		hostIDs := make([]int64, 0, len(byHost))
		for id := range byHost {
			hostIDs = append(hostIDs, id)
		}
		sort.Slice(hostIDs, func(i, j int) bool { return hostIDs[i] < hostIDs[j] })
		for _, id := range hostIDs {
			identity := BloodHoundHostIdentity(byHost[id])
			if identity == "" {
				continue
			}

			var exists int
			err := tx.QueryRowContext(ctx, `SELECT 1 FROM bloodhound_targets WHERE kind = 'Computer' AND identity = ? COLLATE NOCASE`, identity).Scan(&exists)
			if err == nil {
				continue
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if _, err := s.saveBloodHoundTarget(ctx, tx, "system", "Computer", identity, &id); err != nil {
				return err
			}
		}
		return nil
	})
}

func BloodHoundHostIdentity(names []model.Hostname) string {
	all := make(map[string]string)
	nxc := make(map[string]string)
	for _, candidate := range names {
		candidate.Name = strings.TrimSuffix(candidate.Name, ".")
		if !validDirectoryDomain(candidate.Name, true) {
			continue
		}
		key := strings.ToLower(candidate.Name)
		all[key] = candidate.Name
		if candidate.Source == "nxc" {
			nxc[key] = candidate.Name
		}
	}
	if len(nxc) > 0 {
		all = nxc
	}
	if len(all) == 1 {
		for _, name := range all {
			return name
		}
	}
	return ""
}
