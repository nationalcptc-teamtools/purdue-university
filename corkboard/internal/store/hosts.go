package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"corkboard/internal/ingest"
	"corkboard/internal/model"
)

var (
	ErrAlreadyClaimed = errors.New("already claimed by someone else; use --steal to take it")
	ErrNotOwner       = errors.New("not the current owner")
	ErrUnknownHost    = errors.New("unknown host")
	ErrHostLocked     = errors.New("host is locked (caution zone); unlock it with a reason before claiming")
	ErrUnknownCred    = errors.New("unknown credential")
)

type HostFilter struct {
	Q          string
	Tag        string
	Status     string
	Zone       string
	Owner      string
	Port       int
	Service    string
	HasCred    bool
	Sort       string
	Limit      int
	IncludeOut bool
}

func (f *HostFilter) normalize() {
	if f.Sort != "priority" && f.Sort != "last_seen" {
		f.Sort = "ip"
	}
	if f.Limit <= 0 {
		f.Limit = 500
	}
}

func (s *Store) ListHosts(ctx context.Context, f HostFilter) ([]model.Host, error) {
	f.normalize()
	var conds []string
	var args []any
	if f.Zone != "" {
		conds = append(conds, "h.scope_zone = ?")
		args = append(args, f.Zone)
	} else if !f.IncludeOut {
		conds = append(conds, "h.scope_zone != 'out'")
	}
	if f.Status != "" {
		conds = append(conds, "h.status = ?")
		args = append(args, f.Status)
	}

	const childClaim = "EXISTS (SELECT 1 FROM target_claims c JOIN target_details d ON d.id = c.target_id WHERE d.host_id = h.id"
	if f.Owner == "(none)" {
		conds = append(conds, "COALESCE(h.owner, '') = '' AND NOT "+childClaim+")")
	} else if f.Owner != "" {
		conds = append(conds, "(h.owner = ? OR "+childClaim+" AND c.owner = ?))")
		args = append(args, f.Owner, f.Owner)
	}
	if f.Tag != "" {
		conds = append(conds, "EXISTS (SELECT 1 FROM host_tags ht WHERE ht.host_id = h.id AND ht.tag = ? COLLATE NOCASE)")
		args = append(args, f.Tag)
	}
	if f.Port > 0 {
		conds = append(conds, "EXISTS (SELECT 1 FROM services sv WHERE sv.host_id = h.id AND sv.port = ? AND sv.state != 'closed')")
		args = append(args, f.Port)
	}
	if f.Service != "" {
		conds = append(conds, "EXISTS (SELECT 1 FROM services sv WHERE sv.host_id = h.id AND sv.name = ? COLLATE NOCASE)")
		args = append(args, f.Service)
	}
	if f.HasCred {
		conds = append(conds, "EXISTS (SELECT 1 FROM cred_access ca WHERE ca.host_id = h.id AND ca.level != 'invalid')")
	}
	if f.Q != "" {
		q := "%" + escapeLike(f.Q) + "%"
		conds = append(conds, `(h.ip LIKE ? ESCAPE '\' OR
			EXISTS (SELECT 1 FROM hostnames hn WHERE hn.host_id = h.id AND hn.name LIKE ? ESCAPE '\' COLLATE NOCASE) OR
			EXISTS (SELECT 1 FROM host_tags ht WHERE ht.host_id = h.id AND ht.tag LIKE ? ESCAPE '\' COLLATE NOCASE) OR
			EXISTS (SELECT 1 FROM services sv WHERE sv.host_id = h.id AND sv.name LIKE ? ESCAPE '\' COLLATE NOCASE) OR
			EXISTS (SELECT 1 FROM web_results wr WHERE wr.host_id = h.id AND wr.title LIKE ? ESCAPE '\' COLLATE NOCASE))`)
		args = append(args, q, q, q, q, q)
	}

	var order string
	switch f.Sort {
	case "priority":
		order = "h.priority, h.ip_sort"
	case "last_seen":
		order = "h.last_seen DESC"
	default:
		order = "h.ip_sort"
	}

	query := `SELECT h.id, h.ip, h.os, h.os_accuracy, h.domain, h.mac, h.mac_vendor,
		h.status, h.scope_zone, h.owner, h.claimed_at, h.priority, h.first_seen, h.last_seen, h.updated_at,
		(SELECT COUNT(*) FROM services sv WHERE sv.host_id = h.id AND sv.state != 'closed' AND NOT ` + dynamicRPCCond + `),
		(SELECT COUNT(*) FROM services sv WHERE sv.host_id = h.id AND sv.state != 'closed' AND NOT ` + dynamicRPCCond + ` AND sv.explored_at IS NOT NULL)
	 FROM hosts h` +
		whereClause(conds) +
		" ORDER BY " + order + " LIMIT ?"
	args = append(args, f.Limit)

	rows, err := s.db.Read.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	hosts := make([]model.Host, 0, 64)
	for rows.Next() {
		var h model.Host
		var osStr sql.NullString
		var osAcc sql.NullInt64
		var domain, mac, macV sql.NullString
		var owner sql.NullString
		var claimedAt sql.NullInt64
		if err := rows.Scan(&h.ID, &h.IP, &osStr, &osAcc, &domain, &mac, &macV,
			&h.Status, &h.Zone, &owner, &claimedAt, &h.Priority, &h.FirstSeen, &h.LastSeen, &h.UpdatedAt,
			&h.Services, &h.Explored); err != nil {
			return nil, err
		}
		h.OS = osStr.String
		if osAcc.Valid {
			v := int(osAcc.Int64)
			h.OSAccuracy = &v
		}
		h.Domain, h.MAC, h.MACVendor = domain.String, mac.String, macV.String
		h.Owner = owner.String
		h.ClaimedAt = claimedAt.Int64
		hosts = append(hosts, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(hosts) > 0 {
		if err := s.attachHostNames(ctx, hosts); err != nil {
			return nil, err
		}
		if err := s.attachTags(ctx, hosts); err != nil {
			return nil, err
		}
		if err := s.attachClaims(ctx, hosts); err != nil {
			return nil, err
		}
	}
	return hosts, nil
}

func whereClause(conds []string) string {
	if len(conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(conds, " AND ")
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

func (s *Store) attachHostNames(ctx context.Context, hosts []model.Host) error {
	ids := make([]any, len(hosts))
	for i, h := range hosts {
		ids[i] = h.ID
	}
	q := `SELECT host_id, name, source FROM hostnames WHERE host_id IN (` + placeholders(len(hosts)) + `) ORDER BY name`
	rows, err := s.db.Read.QueryContext(ctx, q, ids...)
	if err != nil {
		return err
	}
	defer rows.Close()
	byID := make(map[int64]*model.Host, len(hosts))
	for i := range hosts {
		byID[hosts[i].ID] = &hosts[i]
	}
	for rows.Next() {
		var hostID int64
		var hn model.Hostname
		if err := rows.Scan(&hostID, &hn.Name, &hn.Source); err != nil {
			return err
		}
		if h, ok := byID[hostID]; ok {
			h.Hostnames = append(h.Hostnames, hn)
		}
	}
	return rows.Err()
}

func (s *Store) attachTags(ctx context.Context, hosts []model.Host) error {
	ids := make([]any, len(hosts))
	for i, h := range hosts {
		ids[i] = h.ID
	}
	q := `SELECT host_id, tag FROM host_tags WHERE host_id IN (` + placeholders(len(hosts)) + `) ORDER BY tag`
	rows, err := s.db.Read.QueryContext(ctx, q, ids...)
	if err != nil {
		return err
	}
	defer rows.Close()
	byID := make(map[int64]*model.Host, len(hosts))
	for i := range hosts {
		byID[hosts[i].ID] = &hosts[i]
	}
	for rows.Next() {
		var hostID int64
		var tag string
		if err := rows.Scan(&hostID, &tag); err != nil {
			return err
		}
		if h, ok := byID[hostID]; ok {
			h.Tags = append(h.Tags, tag)
		}
	}
	return rows.Err()
}

func placeholders(n int) string {
	return strings.TrimRight(strings.Repeat("?,", n), ",")
}

func (s *Store) GetHost(ctx context.Context, ip string) (*model.HostDetail, error) {
	var id int64
	err := s.db.Read.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip = ?`, ip).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUnknownHost
	}
	if err != nil {
		return nil, err
	}
	return s.GetHostByID(ctx, id)
}

func (s *Store) GetHostByID(ctx context.Context, id int64) (*model.HostDetail, error) {
	d := &model.HostDetail{}
	row := s.db.Read.QueryRowContext(ctx,
		`SELECT id, ip, os, os_accuracy, domain, mac, mac_vendor, status, scope_zone, owner, claimed_at,
		 priority, first_seen, last_seen, updated_at FROM hosts WHERE id = ?`, id)
	var osStr sql.NullString
	var osAcc sql.NullInt64
	var domain, mac, macV sql.NullString
	var owner sql.NullString
	var claimedAt sql.NullInt64
	err := row.Scan(&d.Host.ID, &d.Host.IP, &osStr, &osAcc, &domain, &mac, &macV,
		&d.Host.Status, &d.Host.Zone, &owner, &claimedAt, &d.Host.Priority,
		&d.Host.FirstSeen, &d.Host.LastSeen, &d.Host.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUnknownHost
	}
	if err != nil {
		return nil, err
	}
	d.Host.OS = osStr.String
	if osAcc.Valid {
		v := int(osAcc.Int64)
		d.Host.OSAccuracy = &v
	}
	d.Host.Domain, d.Host.MAC, d.Host.MACVendor = domain.String, mac.String, macV.String
	d.Host.Owner = owner.String
	d.Host.ClaimedAt = claimedAt.Int64

	tmp := []model.Host{d.Host}
	if err := s.attachHostNames(ctx, tmp); err != nil {
		return nil, err
	}
	if err := s.attachTags(ctx, tmp); err != nil {
		return nil, err
	}
	if err := s.attachClaims(ctx, tmp); err != nil {
		return nil, err
	}
	d.Host = tmp[0]

	d.Host.Attrs = map[string]string{}
	rows, err := s.db.Read.QueryContext(ctx, `SELECT key, value FROM host_attrs WHERE host_id = ?`, d.Host.ID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return nil, err
		}
		d.Host.Attrs[k] = v
	}
	rows.Close()

	srows, err := s.db.Read.QueryContext(ctx,
		`SELECT id, host_id, proto, port, state, name, product, version, extrainfo, tunnel, cpe, first_seen, last_seen,
		        explored_at, IFNULL(explored_by, '')
		 FROM services WHERE host_id = ? ORDER BY port, proto`, d.Host.ID)
	if err != nil {
		return nil, err
	}
	for srows.Next() {
		var sv model.Service
		var name, product, version, extra, tunnel, cpe sql.NullString
		if err := srows.Scan(&sv.ID, &sv.HostID, &sv.Proto, &sv.Port, &sv.State,
			&name, &product, &version, &extra, &tunnel, &cpe, &sv.FirstSeen, &sv.LastSeen,
			&sv.ExploredAt, &sv.ExploredBy); err != nil {
			srows.Close()
			return nil, err
		}
		sv.Name, sv.Product, sv.Version = name.String, product.String, version.String
		sv.ExtraInfo, sv.Tunnel = extra.String, tunnel.String
		sv.Type = model.ServiceType(sv)
		if cpe.Valid && cpe.String != "" {
			_ = json.Unmarshal([]byte(cpe.String), &sv.CPE)
		}
		d.Services = append(d.Services, sv)
	}
	srows.Close()
	if err := srows.Err(); err != nil {
		return nil, err
	}
	if len(d.Services) > 0 {
		ids := make([]any, len(d.Services))
		for i, sv := range d.Services {
			ids[i] = sv.ID
		}
		drows, err := s.db.Read.QueryContext(ctx,
			`SELECT service_id, script_id, output FROM service_scripts
			 WHERE service_id IN (`+placeholders(len(ids))+`)`, ids...)
		if err != nil {
			return nil, err
		}
		svByID := make(map[int64]*model.Service, len(d.Services))
		for i := range d.Services {
			svByID[d.Services[i].ID] = &d.Services[i]
		}
		for drows.Next() {
			var sid int64
			var sc model.Script
			if err := drows.Scan(&sid, &sc.ID, &sc.Output); err != nil {
				drows.Close()
				return nil, err
			}
			if sv, ok := svByID[sid]; ok {
				sv.Scripts = append(sv.Scripts, sc)
			}
		}
		drows.Close()
		if err := drows.Err(); err != nil {
			return nil, err
		}
	}

	hrows, err := s.db.Read.QueryContext(ctx,
		`SELECT script_id, output FROM service_scripts
		 WHERE host_id = ? AND service_id IS NULL ORDER BY script_id`, d.Host.ID)
	if err != nil {
		return nil, err
	}
	for hrows.Next() {
		var sc model.Script
		if err := hrows.Scan(&sc.ID, &sc.Output); err != nil {
			hrows.Close()
			return nil, err
		}
		d.HostScripts = append(d.HostScripts, sc)
	}
	hrows.Close()
	if err := hrows.Err(); err != nil {
		return nil, err
	}

	wrows, err := s.db.Read.QueryContext(ctx,
		`SELECT id, url, final_url, status_code, title, technologies, failed, failed_reason, probed_at,
		        IFNULL(screenshot, ''), IFNULL(thumb, ''), IFNULL(tls_subject, '')
		 FROM web_results WHERE host_id = ? ORDER BY url`, d.Host.ID)
	if err != nil {
		return nil, err
	}
	for wrows.Next() {
		var w model.WebResult
		var title, tech, reason, finalURL sql.NullString
		if err := wrows.Scan(&w.ID, &w.URL, &finalURL, &w.StatusCode, &title, &tech, &w.Failed, &reason, &w.ProbedAt, &w.Screenshot, &w.Thumb, &w.TLSSubject); err != nil {
			wrows.Close()
			return nil, err
		}
		w.Title, w.FinalURL, w.FailedReason = title.String, finalURL.String, reason.String
		if tech.Valid && tech.String != "" {
			_ = json.Unmarshal([]byte(tech.String), &w.Technologies)
		}
		d.Web = append(d.Web, w)
	}
	wrows.Close()
	if err := wrows.Err(); err != nil {
		return nil, err
	}

	crows, err := s.db.Read.QueryContext(ctx,
		`SELECT c.id, c.domain, c.username, c.secret, c.secret_type, c.source, c.notes, c.added_by, c.added_at,
			ca.protocol, ca.level, ca.observed_at
		 FROM creds c JOIN cred_access ca ON ca.cred_id = c.id
		 WHERE ca.host_id = ? AND ca.level != 'invalid'
		 ORDER BY c.username, ca.protocol`, d.Host.ID)
	if err != nil {
		return nil, err
	}

	credByID := map[int64]int{}
	for crows.Next() {
		var c model.Cred
		var a model.CredAccess
		var notes sql.NullString
		if err := crows.Scan(&c.ID, &c.Domain, &c.Username, &c.Secret, &c.SecretType, &c.Source,
			&notes, &c.AddedBy, &c.AddedAt, &a.Protocol, &a.Level, &a.ObservedAt); err != nil {
			crows.Close()
			return nil, err
		}
		c.Notes = notes.String
		a.HostID = d.Host.ID
		a.IP = d.Host.IP
		if i, ok := credByID[c.ID]; ok {
			d.Creds[i].Access = append(d.Creds[i].Access, a)
			continue
		}
		c.Access = []model.CredAccess{a}
		d.Creds = append(d.Creds, c)
		credByID[c.ID] = len(d.Creds) - 1
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return nil, err
	}

	shrows, err := s.db.Read.QueryContext(ctx,
		`SELECT id, name, remark, cred_id, can_read, can_write, observed_at
		 FROM shares WHERE host_id = ? ORDER BY name`, d.Host.ID)
	if err != nil {
		return nil, err
	}
	for shrows.Next() {
		var sh model.Share
		var remark sql.NullString
		var credID sql.NullInt64
		var canRead, canWrite int
		if err := shrows.Scan(&sh.ID, &sh.Name, &remark, &credID, &canRead, &canWrite, &sh.ObservedAt); err != nil {
			shrows.Close()
			return nil, err
		}
		sh.Remark = remark.String
		if credID.Valid {
			v := credID.Int64
			sh.CredID = &v
		}
		sh.CanRead, sh.CanWrite = canRead != 0, canWrite != 0
		d.Shares = append(d.Shares, sh)
	}
	shrows.Close()
	if err := shrows.Err(); err != nil {
		return nil, err
	}

	trows, err := s.db.Read.QueryContext(ctx,
		`SELECT id, dedupe_key, rule_id, host_id, service_id, title, body, commands, priority, state, owner, claimed_at, created_at, updated_at, closed_note
		 FROM tasks WHERE host_id = ? ORDER BY priority, created_at`, d.Host.ID)
	if err != nil {
		return nil, err
	}
	for trows.Next() {
		var t model.Task
		var ruleID, owner, closedNote sql.NullString
		var hostID, serviceID, claimedAt sql.NullInt64
		var commands sql.NullString
		if err := trows.Scan(&t.ID, &t.DedupeKey, &ruleID, &hostID, &serviceID, &t.Title, &t.Body,
			&commands, &t.Priority, &t.State, &owner, &claimedAt, &t.CreatedAt, &t.UpdatedAt, &closedNote); err != nil {
			trows.Close()
			return nil, err
		}
		t.RuleID, t.Owner, t.ClosedNote = ruleID.String, owner.String, closedNote.String
		if serviceID.Valid {
			v := serviceID.Int64
			t.ServiceID = &v
		}
		t.ClaimedAt = claimedAt.Int64
		if commands.Valid && commands.String != "" {
			_ = json.Unmarshal([]byte(commands.String), &t.Commands)
		}
		t.HostIP = d.Host.IP
		d.Tasks = append(d.Tasks, t)
	}
	trows.Close()
	if err := trows.Err(); err != nil {
		return nil, err
	}

	nrows, err := s.db.Read.QueryContext(ctx,
		`SELECT n.id, n.service_id, IFNULL(sv.port || '/' || sv.proto, ''), n.author, n.body, n.outcome, n.command, n.output, n.created_at
		 FROM notes n LEFT JOIN services sv ON sv.id = n.service_id
		 WHERE n.host_id = ? ORDER BY n.created_at DESC, n.id DESC`, d.Host.ID)
	if err != nil {
		return nil, err
	}
	for nrows.Next() {
		var n model.Note
		if err := nrows.Scan(&n.ID, &n.ServiceID, &n.Service, &n.Author, &n.Body, &n.Outcome, &n.Command, &n.Output, &n.CreatedAt); err != nil {
			nrows.Close()
			return nil, err
		}
		n.HostID = d.Host.ID
		d.Notes = append(d.Notes, n)
	}
	nrows.Close()
	if err := nrows.Err(); err != nil {
		return nil, err
	}

	orows, err := s.db.Read.QueryContext(ctx,
		`SELECT id, level, via_finding_id, via_cred_id, via_text, by_user, at
		 FROM compromises WHERE host_id = ? ORDER BY at`, d.Host.ID)
	if err != nil {
		return nil, err
	}
	for orows.Next() {
		var o model.Compromise
		var vf, vc sql.NullInt64
		if err := orows.Scan(&o.ID, &o.Level, &vf, &vc, &o.ViaText, &o.ByUser, &o.At); err != nil {
			orows.Close()
			return nil, err
		}
		if vf.Valid {
			v := vf.Int64
			o.ViaFindingID = &v
		}
		if vc.Valid {
			v := vc.Int64
			o.ViaCredID = &v
		}
		o.HostID, o.IP = d.Host.ID, d.Host.IP
		d.Compromises = append(d.Compromises, o)
	}
	orows.Close()
	if err := orows.Err(); err != nil {
		return nil, err
	}

	erows, err := s.db.Read.QueryContext(ctx,
		`SELECT id, at, actor, kind, host_id, ref_id, summary, data FROM events
		 WHERE host_id = ? ORDER BY at DESC, id DESC LIMIT 200`, d.Host.ID)
	if err != nil {
		return nil, err
	}
	for erows.Next() {
		var e model.Event
		var hostID, refID sql.NullInt64
		var data sql.NullString
		if err := erows.Scan(&e.ID, &e.At, &e.Actor, &e.Kind, &hostID, &refID, &e.Summary, &data); err != nil {
			erows.Close()
			return nil, err
		}
		if hostID.Valid {
			v := hostID.Int64
			e.HostID = &v
		}
		if refID.Valid {
			v := refID.Int64
			e.RefID = &v
		}
		e.Data = data.String
		d.Timeline = append(d.Timeline, e)
	}
	erows.Close()
	if err := erows.Err(); err != nil {
		return nil, err
	}
	d.ScanHistory, err = s.ScanHistory(ctx, d.Host.IP)
	if err != nil {
		return nil, err
	}
	for _, r := range d.ScanHistory {
		d.OSEvidence = append(d.OSEvidence, r.Host.OSEvidence...)
		for i := range d.Services {
			for _, svc := range r.Host.Services {
				if svc.Port == d.Services[i].Port && svc.Proto == d.Services[i].Proto && svc.Method != "" && (d.Services[i].Method == "" || d.Services[i].Method != "probed" && svc.Method == "probed") {
					d.Services[i].Method = svc.Method
					d.Services[i].Confidence = svc.Confidence
				}
			}
		}
	}
	return d, nil
}

func (s *Store) ClaimHost(ctx context.Context, ip, user string, steal bool) error {
	now := s.nowMS()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var owner sql.NullString
		var status string
		err := tx.QueryRowContext(ctx, `SELECT owner, status FROM hosts WHERE ip = ?`, ip).Scan(&owner, &status)
		ownerS := owner.String
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownHost
		}
		if err != nil {
			return err
		}
		if status == "locked" {
			return ErrHostLocked
		}
		kind := EventClaim
		if ownerS != "" && ownerS != user {
			if !steal {
				return fmt.Errorf("%w: %s", ErrAlreadyClaimed, ownerS)
			}
			kind = EventSteal
		}
		newStatus := status
		if status == "untouched" {
			newStatus = "in_progress"
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE hosts SET owner = ?, claimed_at = ?, status = ?, updated_at = ? WHERE ip = ?`,
			user, now, newStatus, now, ip); err != nil {
			return err
		}
		var hostID int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip = ?`, ip).Scan(&hostID); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, now, user, kind, &hostID, nil, fmt.Sprintf("%s claimed %s", user, ip), "{}")
	})
}

func (s *Store) ReleaseHost(ctx context.Context, ip, user string) error {
	now := s.nowMS()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var owner sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT owner FROM hosts WHERE ip = ?`, ip).Scan(&owner)
		ownerS := owner.String
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownHost
		}
		if err != nil {
			return err
		}
		if ownerS != user {
			return ErrNotOwner
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE hosts SET owner = NULL, claimed_at = NULL, updated_at = ? WHERE ip = ?`, now, ip); err != nil {
			return err
		}
		var hostID int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip = ?`, ip).Scan(&hostID); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, now, user, EventRelease, &hostID, nil, fmt.Sprintf("%s released %s", user, ip), "{}")
	})
}

func (s *Store) SetStatus(ctx context.Context, ip, user, status, reason string) error {
	switch status {
	case "untouched", "in_progress", "done", "compromised", "locked":
	default:
		return fmt.Errorf("invalid status %q", status)
	}
	now := s.nowMS()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var old string
		err := tx.QueryRowContext(ctx, `SELECT status FROM hosts WHERE ip = ?`, ip).Scan(&old)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownHost
		}
		if err != nil {
			return err
		}
		if old == "locked" && status != "locked" && reason == "" {
			return fmt.Errorf("unlocking a locked host requires a reason")
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE hosts SET status = ?, updated_at = ? WHERE ip = ?`, status, now, ip); err != nil {
			return err
		}
		var hostID int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip = ?`, ip).Scan(&hostID); err != nil {
			return err
		}
		if old == "locked" && status != "locked" {

			if _, err := tx.ExecContext(ctx,
				`INSERT INTO host_attrs (host_id, key, value, source, updated_at) VALUES (?, 'unlocked_by', ?, ?, ?)
				 ON CONFLICT(host_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
				hostID, user+":"+reason, "manual", now); err != nil {
				return err
			}
			return s.appendEvent(ctx, tx, now, user, EventLockChange, &hostID, nil,
				fmt.Sprintf("%s unlocked %s (%s)", user, ip, reason), "{}")
		}
		if status == "locked" {
			return s.appendEvent(ctx, tx, now, user, EventLockChange, &hostID, nil,
				fmt.Sprintf("%s locked %s", user, ip), "{}")
		}
		return nil
	})
}

type LogInput struct {
	ServiceID *int64
	Port      int
	Proto     string
	Body      string
	Outcome   string
	Command   string
	Output    string
}

func (s *Store) AddNote(ctx context.Context, ip, user, body string) error {
	return s.AddLog(ctx, ip, user, LogInput{Body: body})
}

func (s *Store) AddLog(ctx context.Context, ip, user string, in LogInput) error {
	if strings.TrimSpace(in.Body) == "" {
		return fmt.Errorf("%w: a log entry needs text", ErrInvalidInput)
	}
	for _, f := range []string{in.Body, in.Command, in.Output} {
		if len(f) > ingest.MaxNoteBytes {
			return fmt.Errorf("%w: log entry too large (max %d bytes per field)", ErrInvalidInput, ingest.MaxNoteBytes)
		}
	}
	switch in.Outcome {
	case "", "worked", "failed":
	default:
		return fmt.Errorf("%w: outcome must be worked or failed", ErrInvalidInput)
	}
	now := s.nowMS()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var hostID int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip = ?`, ip).Scan(&hostID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownHost
		}
		if err != nil {
			return err
		}
		serviceID, label := in.ServiceID, ""
		if serviceID == nil && in.Port != 0 {
			proto := in.Proto
			if proto == "" {
				proto = "tcp"
			}
			var id int64
			err = tx.QueryRowContext(ctx, `SELECT id FROM services WHERE host_id = ? AND port = ? AND proto = ?`, hostID, in.Port, proto).Scan(&id)
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: %s has no %d/%s service", ErrUnknownService, ip, in.Port, proto)
			}
			if err != nil {
				return err
			}
			serviceID = &id
		}
		if serviceID != nil {
			var port int
			var proto string
			err = tx.QueryRowContext(ctx, `SELECT port, proto FROM services WHERE id = ? AND host_id = ?`, *serviceID, hostID).Scan(&port, &proto)
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: service %d is not on %s", ErrUnknownService, *serviceID, ip)
			}
			if err != nil {
				return err
			}
			label = fmt.Sprintf(":%d/%s", port, proto)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO notes (host_id, service_id, author, body, outcome, command, output, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			hostID, serviceID, user, in.Body, in.Outcome, in.Command, in.Output, now); err != nil {
			return err
		}
		summary := fmt.Sprintf("%s logged on %s%s", user, ip, label)
		if in.Outcome != "" {
			summary += " (" + in.Outcome + ")"
		}
		return s.appendEvent(ctx, tx, now, user, EventNote, &hostID, serviceID, summary, "{}")
	})
}

func (s *Store) SetTags(ctx context.Context, ip, user string, add, remove []string) error {
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var hostID int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip = ?`, ip).Scan(&hostID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownHost
		}
		if err != nil {
			return err
		}
		for _, tag := range add {
			if tag == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO host_tags (host_id, tag, source) VALUES (?, ?, 'manual')
				 ON CONFLICT(host_id, tag) DO UPDATE SET source = 'manual'`, hostID, tag); err != nil {
				return err
			}
		}
		for _, tag := range remove {
			if tag == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM host_tags WHERE host_id = ? AND tag = ? COLLATE NOCASE`, hostID, tag); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) ListHostIDs(ctx context.Context) ([]int64, error) {
	rows, err := s.db.Read.QueryContext(ctx, `SELECT id FROM hosts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) ListEvents(ctx context.Context, sinceID int64, limit int, kinds []string, hostID *int64) ([]model.Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var conds []string
	var args []any
	if sinceID > 0 {
		conds = append(conds, "id < ?")
		args = append(args, sinceID)
	}
	if hostID != nil {
		conds = append(conds, "host_id = ?")
		args = append(args, *hostID)
	}
	if len(kinds) > 0 {
		conds = append(conds, "kind IN ("+placeholders(len(kinds))+")")
		args = append(args, toAny(kinds)...)
	}
	query := `SELECT id, at, actor, kind, host_id, ref_id, summary, data FROM events` +
		whereClause(conds) + " ORDER BY at DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.Read.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Event
	for rows.Next() {
		var e model.Event
		var hID, rID sql.NullInt64
		var data sql.NullString
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Kind, &hID, &rID, &e.Summary, &data); err != nil {
			return nil, err
		}
		if hID.Valid {
			v := hID.Int64
			e.HostID = &v
		}
		if rID.Valid {
			v := rID.Int64
			e.RefID = &v
		}
		e.Data = data.String
		out = append(out, e)
	}
	return out, rows.Err()
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

const dynamicRPCCond = `(sv.proto = 'tcp' AND sv.port >= 49152 AND IFNULL(sv.name, '') IN ('', 'msrpc', 'unknown'))`
