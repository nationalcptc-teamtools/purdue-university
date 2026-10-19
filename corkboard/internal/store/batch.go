package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"corkboard/internal/coverage"
	"corkboard/internal/ingest"
	"corkboard/internal/model"
)

func (s *Store) ApplyBatch(ctx context.Context, actor string, b *ingest.Batch) (ingest.Result, error) {
	var res ingest.Result
	now := s.nowMS()

	res.Warnings = append(res.Warnings, b.Warnings...)
	hostIDs := make(map[string]int64)
	var touched []int64
	servicesSeen := 0
	hasSV := hasVersionDetection(b.Run.Command)

	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		if b.Run.SourceSHA != "" {
			var id int64
			var vantage string
			err := tx.QueryRowContext(ctx, `SELECT id,vantage FROM runs WHERE source_sha256=?`, b.Run.SourceSHA).Scan(&id, &vantage)
			if err == nil {
				if vantage != b.Run.Vantage {
					return fmt.Errorf("artifact already bound to vantage %q", vantage)
				}
				res = ingest.Result{Duplicate: true, RunID: id}
				return nil
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		runRes, err := tx.ExecContext(ctx,
			`INSERT INTO runs (kind, uploaded_by, uploaded_at, started_at, finished_at, command, source_name, source_sha256, stages, stats,vantage)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '{}',?)`,
			b.Run.Kind, actor, now, nullI64(b.Run.StartedAt), nullI64(b.Run.FinishedAt),
			nullStr(b.Run.Command), nullStr(b.Run.SourceName), nullStr(b.Run.SourceSHA),
			jsonOr(coverage.StagesForRun(b.Run)), b.Run.Vantage)
		if err != nil {
			return err
		}
		runID, err := runRes.LastInsertId()
		if err != nil {
			return err
		}
		res.RunID = runID

		for i := range b.Hosts {
			h := b.Hosts[i]

			if h.Scan != nil && !h.Scan.Responded && len(h.Services) == 0 {
				var existing int64
				if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip=?`, h.IP).Scan(&existing); errors.Is(err, sql.ErrNoRows) {
					if err = s.recordScan(ctx, tx, runID, nil, h, b.Run, now); err != nil {
						return err
					}
					continue
				} else if err != nil {
					return err
				}
				for _, alias := range h.Hostnames {
					if alias.Name != "" {
						if _, err := tx.ExecContext(ctx, `INSERT INTO hostnames(host_id,name,source,first_seen) VALUES(?,?,?,?) ON CONFLICT(host_id,name) DO NOTHING`, existing, alias.Name, alias.Source, now); err != nil {
							return err
						}
					}
				}
				if err := s.recordScan(ctx, tx, runID, &existing, h, b.Run, now); err != nil {
					return err
				}
				hostIDs[h.IP] = existing
				continue
			}
			observed := b.Run.ObservedAt(now)
			if h.Scan != nil && h.Scan.At > 0 {
				observed = h.Scan.At
			}
			hostID, isNew, changed, err := s.mergeHost(ctx, tx, h, runID, actor, hasSV, observed, &res)
			if err != nil {
				return err
			}
			if err := s.recordScan(ctx, tx, runID, &hostID, h, b.Run, now); err != nil {
				return err
			}
			hostIDs[h.IP] = hostID
			touched = append(touched, hostID)
			if isNew {
				res.NewHosts++
				if err := s.appendEvent(ctx, tx, now, actor, EventHostNew, &hostID, nil,
					"new host "+h.IP, jsonOr(map[string]string{"ip": h.IP})); err != nil {
					return err
				}
			} else if changed {
				res.UpdatedHosts++
			}
			servicesSeen += len(h.Services)
		}

		credIDs := make(map[string]int64)
		for i := range b.Creds {
			c := b.Creds[i]
			ref := c.Ref
			if ref == "" {
				ref = fmt.Sprintf("cred:%d", i)
			}
			id, isNew, err := upsertCred(ctx, tx, c, actor, now)
			if err != nil {
				return err
			}
			credIDs[ref] = id
			if isNew {
				res.NewCreds++
				if err := s.appendEvent(ctx, tx, now, actor, EventCredNew, nil, &id,
					"new credential "+model.CredName(c.Domain, c.Username),
					jsonOr(map[string]int64{"cred_id": id})); err != nil {
					return err
				}
			}
		}

		if err := s.mergeAccess(ctx, tx, b, credIDs, hostIDs, runID, now, &res); err != nil {
			return err
		}

		if err := s.mergeShares(ctx, tx, b, credIDs, hostIDs, now); err != nil {
			return err
		}

		if err := s.mergeWebResults(ctx, tx, b, hostIDs, runID, now); err != nil {
			return err
		}

		if err := s.mergeVulns(ctx, tx, b, hostIDs, now, actor); err != nil {
			return err
		}

		if err := s.mergeCoverage(ctx, tx, b, hostIDs, runID); err != nil {
			return err
		}

		authHosts := make([]int64, 0, len(hostIDs))
		for _, hid := range hostIDs {
			authHosts = append(authHosts, hid)
		}

		reported := make(map[int64]string)
		for _, h := range b.Hosts {
			if hid, ok := hostIDs[h.IP]; ok && h.Domain != "" {
				reported[hid] = h.Domain
			}
		}
		if err = s.syncAuthHosts(ctx, tx, authHosts, reported, actor, authIdentityTime(b.Run, now)); err != nil {
			return err
		}
		for _, a := range b.Access {
			cid, ok := credIDs[a.CredRef]
			if !ok {
				continue
			}
			var hid int64
			if err = tx.QueryRowContext(ctx, "SELECT id FROM hosts WHERE ip=?", a.IP).Scan(&hid); err != nil {
				continue
			}
			if !validAccessLevels[a.Level] {
				continue
			}
			var occurred *int64
			if a.ObservedAt > 0 {
				n := a.ObservedAt
				occurred = &n
			}
			if err = s.recordAccessObservation(ctx, tx, actor, cid, hid, a.Protocol, a.Level, b.Run.Vantage, b.Run.Kind, &runID, occurred); err != nil {
				return err
			}
		}

		if _, err := tx.ExecContext(ctx, `UPDATE runs SET stats = ? WHERE id = ?`,
			jsonOr(map[string]int{
				"hosts_seen":    len(b.Hosts),
				"services_seen": servicesSeen,
				"new_hosts":     res.NewHosts,
				"new_services":  res.NewServices,
				"new_creds":     res.NewCreds,
			}), runID); err != nil {
			return err
		}

		summary := fmt.Sprintf("%s ingested %s: %d hosts (%d new), %d services (%d new)",
			actor, b.Run.Kind, len(b.Hosts), res.NewHosts, servicesSeen, res.NewServices)
		return s.appendEvent(ctx, tx, now, actor, EventIngest, nil, &runID, summary,
			jsonOr(map[string]int64{"run_id": runID}))
	})
	if err != nil {
		return res, err
	}
	res.SetTouched(touched)
	return res, nil
}

func hasVersionDetection(command string) bool {
	for _, f := range strings.Fields(command) {
		if f == "-sV" || f == "-A" {
			return true
		}
	}
	return false
}

func nullStr(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func nullI64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullAcc(a int) any {
	if a <= 0 {
		return nil
	}
	return a
}

func boolI(b bool) int {
	if b {
		return 1
	}
	return 0
}

func i64or(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func (s *Store) mergeHost(ctx context.Context, tx *sql.Tx, h ingest.HostObs, runID int64, actor string, hasSV bool, now int64, res *ingest.Result) (id int64, isNew, changed bool, err error) {
	addr, err := netip.ParseAddr(h.IP)
	if err != nil {
		return 0, false, false, fmt.Errorf("host %q: %w", h.IP, err)
	}
	a16 := addr.As16()
	ipSort := a16[:]

	var (
		osStr  sql.NullString
		osAcc  sql.NullInt64
		domain sql.NullString
		mac    sql.NullString
		macV   sql.NullString
	)
	err = tx.QueryRowContext(ctx,
		`SELECT id, os, os_accuracy, domain, mac, mac_vendor FROM hosts WHERE ip = ?`, h.IP).
		Scan(&id, &osStr, &osAcc, &domain, &mac, &macV)
	if errors.Is(err, sql.ErrNoRows) {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO hosts (ip, ip_sort, os, os_accuracy, domain, mac, mac_vendor, first_seen, last_seen, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			h.IP, ipSort, nullStr(h.OS), nullAcc(h.OSAcc), nullStr(h.Domain), nullStr(h.MAC), nullStr(h.MACVendor), now, now, now)
		if err != nil {
			return 0, false, false, err
		}
		id, err = res.LastInsertId()
		if err != nil {
			return 0, false, false, err
		}
		isNew = true
	} else if err != nil {
		return 0, false, false, err
	} else {

		newOS, newOSAcc := osStr.String, 0
		if osAcc.Valid {
			newOSAcc = int(osAcc.Int64)
		}
		if h.OS != "" {
			if !osStr.Valid || h.OSAcc >= newOSAcc {
				newOS, newOSAcc = h.OS, h.OSAcc
			}
		}
		newDomain := domain.String
		if newDomain == "" && h.Domain != "" {
			newDomain = h.Domain
		}
		newMAC := mac.String
		if newMAC == "" && h.MAC != "" {
			newMAC = h.MAC
		}
		newMACV := macV.String
		if newMACV == "" && h.MACVendor != "" {
			newMACV = h.MACVendor
		}
		changed = newOS != osStr.String || newDomain != domain.String ||
			newMAC != mac.String || newMACV != macV.String

		if _, err := tx.ExecContext(ctx,
			`UPDATE hosts SET ip_sort = ?, os = ?, os_accuracy = ?, domain = ?, mac = ?, mac_vendor = ?,
			 last_seen = MAX(last_seen, ?), updated_at = ? WHERE id = ?`,
			ipSort, nullStr(newOS), nullAcc(newOSAcc), nullStr(newDomain), nullStr(newMAC), nullStr(newMACV), now, now, id); err != nil {
			return 0, false, false, err
		}
	}

	for _, hn := range h.Hostnames {
		if hn.Name == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO hostnames (host_id, name, source, first_seen) VALUES (?, ?, ?, ?)
			 ON CONFLICT(host_id, name) DO NOTHING`,
			id, hn.Name, hn.Source, now); err != nil {
			return 0, false, false, err
		}
	}

	for k, v := range h.Attrs {
		var old sql.NullString
		err := tx.QueryRowContext(ctx,
			`SELECT value FROM host_attrs WHERE host_id = ? AND key = ?`, id, k).Scan(&old)
		if errors.Is(err, sql.ErrNoRows) {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO host_attrs (host_id, key, value, source, updated_at) VALUES (?, ?, ?, ?, ?)`,
				id, k, v, "ingest", now); err != nil {
				return 0, false, false, err
			}
			continue
		}
		if err != nil {
			return 0, false, false, err
		}
		if old.Valid && old.String == v {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE host_attrs SET value = ?, source = ?, updated_at = ? WHERE host_id = ? AND key = ?`,
			v, "ingest", now, id, k); err != nil {
			return 0, false, false, err
		}
		if err := s.observe(ctx, tx, runID, id, nil, "attr",
			jsonOr(map[string]string{"key": k, "old": old.String, "new": v}), now); err != nil {
			return 0, false, false, err
		}
	}

	newSvcs, err := s.mergeServices(ctx, tx, h, id, runID, actor, hasSV, now)
	if err != nil {
		return 0, false, false, err
	}
	res.NewServices += newSvcs

	for _, sc := range h.HostScripts {
		if err := upsertScript(ctx, tx, id, nil, sc, runID, now); err != nil {
			return 0, false, false, err
		}
	}
	return id, isNew, changed, nil
}

func (s *Store) mergeServices(ctx context.Context, tx *sql.Tx, h ingest.HostObs, hostID int64, runID int64, actor string, hasSV bool, now int64) (int, error) {
	newCount := 0
	for _, svc := range h.Services {
		state := svc.State
		if state == "" {
			state = "open"
		}
		var (
			id       int64
			product  sql.NullString
			version  sql.NullString
			extra    sql.NullString
			tunnel   sql.NullString
			name     sql.NullString
			cpe      sql.NullString
			lastSeen int64
		)
		err := tx.QueryRowContext(ctx,
			`SELECT id, product, version, extrainfo, tunnel, name, cpe, last_seen
			 FROM services WHERE host_id = ? AND proto = ? AND port = ?`,
			hostID, svc.Proto, svc.Port).Scan(&id, &product, &version, &extra, &tunnel, &name, &cpe, &lastSeen)
		if errors.Is(err, sql.ErrNoRows) {
			cpeJSON, _ := json.Marshal(svc.CPE)
			res, err := tx.ExecContext(ctx,
				`INSERT INTO services (host_id, proto, port, state, name, product, version, extrainfo, tunnel, cpe, first_seen, last_seen)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				hostID, svc.Proto, svc.Port, state, nullStr(svc.Name), nullStr(svc.Product),
				nullStr(svc.Version), nullStr(svc.ExtraInfo), nullStr(svc.Tunnel),
				cpeJSON, now, now)
			if err != nil {
				return 0, err
			}
			id, err = res.LastInsertId()
			if err != nil {
				return 0, err
			}
			newCount++
			if err := s.observe(ctx, tx, runID, hostID, &id, "port_open",
				jsonOr(map[string]any{"proto": svc.Proto, "port": svc.Port, "name": svc.Name}), now); err != nil {
				return 0, err
			}
			if err := s.appendEvent(ctx, tx, now, actor, EventServiceNew, &hostID, nil,
				fmt.Sprintf("new service %s:%d/%s %s", h.IP, svc.Port, svc.Proto, svc.Name), "{}"); err != nil {
				return 0, err
			}
		} else if err != nil {
			return 0, err
		} else {

			if now < lastSeen {
				continue
			}
			detected := svc.Method == "probed" || (svc.Method == "" && hasSV)

			p := product.String
			if svc.Product != "" && (p == "" || detected) {
				p = svc.Product
			}
			v := version.String
			if svc.Version != "" && (v == "" || detected) {
				v = svc.Version
			}
			e := extra.String
			if svc.ExtraInfo != "" && (e == "" || detected) {
				e = svc.ExtraInfo
			}
			t := tunnel.String
			if svc.Tunnel != "" && (t == "" || detected) {
				t = svc.Tunnel
			}
			n := name.String
			if svc.Name != "" && (n == "" || detected) {
				n = svc.Name
			}
			c := cpe.String
			if len(svc.CPE) > 0 && (c == "" || detected) {
				cpeJSON, _ := json.Marshal(svc.CPE)
				c = string(cpeJSON)
			}
			if _, err := tx.ExecContext(ctx,
				`UPDATE services SET state = ?, name = ?, product = ?, version = ?, extrainfo = ?,
				 tunnel = ?, cpe = ?, last_seen = MAX(last_seen, ?) WHERE id = ?`,
				state, nullStr(n), nullStr(p), nullStr(v), nullStr(e), nullStr(t), nullStr(c), now, id); err != nil {
				return 0, err
			}
		}
		for _, sc := range svc.Scripts {
			if err := upsertScript(ctx, tx, hostID, &id, sc, runID, now); err != nil {
				return 0, err
			}
		}
	}
	return newCount, nil
}

func upsertScript(ctx context.Context, tx *sql.Tx, hostID int64, serviceID *int64, sc ingest.ScriptObs, runID, now int64) error {
	output := ingest.TruncateScriptOutput(sc.Output)
	sid := int64(0)
	if serviceID != nil {
		sid = *serviceID
	}
	var old sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT output FROM service_scripts WHERE host_id = ? AND IFNULL(service_id, 0) = ? AND script_id = ?`,
		hostID, sid, sc.ID).Scan(&old)
	if errors.Is(err, sql.ErrNoRows) {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO service_scripts (service_id, host_id, script_id, output, run_id, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)`, serviceID, hostID, sc.ID, output, runID, now)
		return err
	}
	if err != nil {
		return err
	}
	if old.Valid && old.String == output {
		return nil
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE service_scripts SET output = ?, run_id = ?, updated_at = ?
		 WHERE host_id = ? AND IFNULL(service_id, 0) = ? AND script_id = ?`,
		output, runID, now, hostID, sid, sc.ID)
	return err
}

func (s *Store) observe(ctx context.Context, tx *sql.Tx, runID, hostID int64, serviceID *int64, what, detail string, now int64) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO observations (run_id, host_id, service_id, what, detail, at) VALUES (?, ?, ?, ?, ?, ?)`,
		runID, hostID, serviceID, what, detail, now)
	return err
}

func upsertCred(ctx context.Context, tx *sql.Tx, c ingest.CredObs, actor string, now int64) (int64, bool, error) {
	var id int64
	err := tx.QueryRowContext(ctx,
		`SELECT id FROM creds WHERE domain = ? AND username = ? AND secret = ? AND secret_type = ?`,
		c.Domain, c.Username, c.Secret, c.SecretType).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO creds (domain, username, secret, secret_type, source, added_by, added_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			c.Domain, c.Username, c.Secret, c.SecretType, orDefault(c.Source, "manual"), actor, now)
		if err != nil {
			return 0, false, err
		}
		id, err = res.LastInsertId()
		return id, true, err
	}
	return id, false, err
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func (s *Store) mergeAccess(ctx context.Context, tx *sql.Tx, b *ingest.Batch, credIDs map[string]int64, hostIDs map[string]int64, runID int64, now int64, res *ingest.Result) error {
	for _, a := range b.Access {
		cid, ok := credIDs[a.CredRef]
		if !ok {
			res.Warnings = append(res.Warnings, "access for unknown cred ref "+a.CredRef)
			continue
		}
		hid, ok := hostIDs[a.IP]
		if !ok {
			if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip = ?`, a.IP).Scan(&hid); err != nil {
				res.Warnings = append(res.Warnings, "access for unknown host "+a.IP)
				continue
			}
		}
		newRank, ok := accessRank[a.Level]
		if !ok {
			res.Warnings = append(res.Warnings, "access level "+a.Level+" invalid for "+a.IP)
			continue
		}
		var oldLevel string
		err := tx.QueryRowContext(ctx,
			`SELECT level FROM cred_access WHERE cred_id = ? AND host_id = ? AND protocol = ?`,
			cid, hid, a.Protocol).Scan(&oldLevel)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO cred_access (cred_id, host_id, protocol, level, source, observed_at)
				 VALUES (?, ?, ?, ?, ?, ?)`, cid, hid, a.Protocol, a.Level, b.Run.Kind, now); err != nil {
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
					a.Level, b.Run.Kind, now, cid, hid, a.Protocol); err != nil {
					return err
				}
			}
		}
		if a.Level == "admin" && oldLevel != "admin" {
			if err := s.appendEvent(ctx, tx, now, "system", EventCredAccessAdmin, &hid, &cid,
				fmt.Sprintf("admin access as %s on %s (%s)", credNameTx(ctx, tx, cid), a.IP, a.Protocol), "{}"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) mergeShares(ctx context.Context, tx *sql.Tx, b *ingest.Batch, credIDs map[string]int64, hostIDs map[string]int64, now int64) error {
	for _, sh := range b.Shares {
		hid, ok := hostIDs[sh.IP]
		if !ok {
			if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip = ?`, sh.IP).Scan(&hid); err != nil {
				continue
			}
		}
		var credID *int64
		if sh.CredRef != "" {
			if cid, ok := credIDs[sh.CredRef]; ok {
				credID = &cid
			}
		}
		var id int64
		err := tx.QueryRowContext(ctx,
			`SELECT id FROM shares WHERE host_id = ? AND name = ? AND IFNULL(cred_id, 0) = ?`,
			hid, sh.Name, i64or(credID)).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			_, err = tx.ExecContext(ctx,
				`INSERT INTO shares (host_id, name, remark, cred_id, can_read, can_write, observed_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?)`,
				hid, sh.Name, nullStr(sh.Remark), credID, boolI(sh.Read), boolI(sh.Write), now)
			return err
		}
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE shares SET remark = ?, can_read = ?, can_write = ?, observed_at = ? WHERE id = ?`,
			nullStr(sh.Remark), boolI(sh.Read), boolI(sh.Write), now, id)
		return err
	}
	return nil
}

func (s *Store) mergeWebResults(ctx context.Context, tx *sql.Tx, b *ingest.Batch, hostIDs map[string]int64, runID, now int64) error {
	for _, w := range b.WebResults {
		var hostID *int64
		var serviceID *int64
		if u, err := url.Parse(w.URL); err == nil && u.Host != "" {
			host := u.Hostname()
			port := u.Port()
			if port == "" {
				if u.Scheme == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
			portN, _ := strconv.Atoi(port)
			var hid int64
			var resolved bool
			if addr, err := netip.ParseAddr(host); err == nil {

				if id, ok := hostIDs[addr.String()]; ok {
					hid, resolved = id, true
				} else if err := tx.QueryRowContext(ctx,
					`SELECT id FROM hosts WHERE ip = ?`, addr.String()).Scan(&hid); err == nil {
					resolved = true
				}
			} else if err := tx.QueryRowContext(ctx,
				`SELECT h.id FROM hosts h JOIN hostnames hn ON hn.host_id = h.id
				 WHERE hn.name = ? COLLATE NOCASE LIMIT 1`, host).Scan(&hid); err == nil {
				resolved = true
			}
			if resolved {
				hostID = &hid
			}
			if hostID != nil && portN > 0 {
				var sid int64
				err := tx.QueryRowContext(ctx,
					`SELECT id FROM services WHERE host_id = ? AND port = ? AND state != 'closed'
					 ORDER BY CASE WHEN name IN ('http','https') THEN 0 ELSE 1 END, id LIMIT 1`,
					*hostID, portN).Scan(&sid)
				if err == nil {
					serviceID = &sid
				}
			}
		}
		tj, _ := json.Marshal(w.Technologies)
		if len(w.Technologies) == 0 {
			tj = []byte("[]")
		}
		sans, _ := json.Marshal(w.TLSSANs)
		if len(w.TLSSANs) == 0 {
			sans = []byte("[]")
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO web_results (service_id, host_id, url, final_url, status_code, title, technologies,
			 tls_subject, tls_sans, screenshot, failed, failed_reason, run_id, probed_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(url) DO UPDATE SET
			 final_url = excluded.final_url, status_code = excluded.status_code,
			 title = excluded.title, technologies = excluded.technologies,
			 tls_subject = excluded.tls_subject, tls_sans = excluded.tls_sans,
			 screenshot = excluded.screenshot, failed = excluded.failed,
			 failed_reason = excluded.failed_reason, run_id = excluded.run_id,
			 probed_at = excluded.probed_at,
			 host_id = COALESCE(excluded.host_id, host_id),
			 service_id = COALESCE(excluded.service_id, service_id)`,
			serviceID, hostID, w.URL, nullStr(w.FinalURL), w.StatusCode, nullStr(w.Title),
			string(tj), nullStr(w.TLSSubject), string(sans), nullStr(w.ScreenshotSHA),
			boolI(w.Failed), nullStr(w.FailedReason), runID, nullI64(w.ProbedAt))
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) mergeVulns(ctx context.Context, tx *sql.Tx, b *ingest.Batch, hostIDs map[string]int64, now int64, actor string) error {
	sev := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	for _, v := range b.Vulns {
		severity := v.Severity
		if !sev[severity] {
			severity = "info"
		}
		dedupe := "nuclei:" + v.TemplateID
		var fid int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM findings WHERE dedupe_key = ?`, dedupe).Scan(&fid)
		if errors.Is(err, sql.ErrNoRows) {
			res, err := tx.ExecContext(ctx,
				`INSERT INTO findings (dedupe_key, title, severity, source, state, description, created_at, updated_at)
				 VALUES (?, ?, ?, 'nuclei', 'candidate', ?, ?, ?)`,
				dedupe, v.Name, severity, v.Description, now, now)
			if err != nil {
				return err
			}
			fid, err = res.LastInsertId()
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			if _, err := tx.ExecContext(ctx,
				`UPDATE findings SET severity = ?, updated_at = ? WHERE id = ? AND operator_edited=0`, severity, now, fid); err != nil {
				return err
			}
		}
		fid, err = resolveFindingTx(ctx, tx, fid)
		if err != nil {
			return err
		}
		var hostID *int64
		var serviceID *int64
		if hid, ok := hostIDs[v.IP]; ok {
			hostID = &hid
		} else {
			var hid int64
			if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip = ?`, v.IP).Scan(&hid); err == nil {
				hostID = &hid
			}
		}
		if hostID != nil && v.Port > 0 {
			var sid int64
			if err := tx.QueryRowContext(ctx,
				`SELECT id FROM services WHERE host_id = ? AND port = ? AND state != 'closed' LIMIT 1`,
				*hostID, v.Port).Scan(&sid); err == nil {
				serviceID = &sid
			}
		}
		evidence := v.MatchedAt
		if v.Extracted != "" {
			evidence += "\n" + v.Extracted
		}
		if len(evidence) > ingest.MaxEvidenceBytes {
			evidence = evidence[:ingest.MaxEvidenceBytes-len(" [truncated]")] + " [truncated]"
		}

		if hostID != nil {
			if err = s.importFindingTarget(ctx, tx, fid, actor, *hostID, serviceID, evidence); err != nil {
				return err
			}
			var fhID int64
			err = tx.QueryRowContext(ctx,
				`SELECT id FROM finding_hosts WHERE finding_id = ? AND host_id = ? AND IFNULL(service_id, 0) = ?`,
				fid, i64or(hostID), i64or(serviceID)).Scan(&fhID)
			if errors.Is(err, sql.ErrNoRows) {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO finding_hosts (finding_id, host_id, service_id, evidence) VALUES (?, ?, ?, ?)`,
					fid, hostID, serviceID, evidence); err != nil {
					return err
				}
			} else if err != nil {
				return err
			} else if _, err := tx.ExecContext(ctx,
				`UPDATE finding_hosts SET evidence = ? WHERE id = ? AND NOT EXISTS(SELECT 1 FROM findings WHERE findings.id=finding_hosts.finding_id AND operator_edited=1)`, evidence, fhID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) mergeCoverage(ctx context.Context, tx *sql.Tx, b *ingest.Batch, hostIDs map[string]int64, runID int64) error {
	for _, h := range b.Hosts {
		hid, ok := hostIDs[h.IP]
		if !ok {
			continue
		}
		for _, stage := range coverage.UniformStages(b.Run) {
			if stage == coverage.StageSvcVersion && b.Run.Kind == "nmap" {
				continue
			}
			status := coverage.HostStageStatus(b.Run, h, stage)
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO run_coverage(run_id,host_id,stage,status) VALUES(?,?,?,?)`, runID, hid, stage, status); err != nil {
				return err
			}
		}
		if b.Run.Kind == "nmap" {
			var total, unknown int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(CASE WHEN COALESCE(services.name,'') IN ('','unknown') OR NOT EXISTS (SELECT 1 FROM service_views v WHERE v.host_id=services.host_id AND v.proto=services.proto AND v.port=services.port AND v.method='probed') THEN 1 ELSE 0 END),0) FROM services WHERE host_id=? AND state IN ('open','open|filtered')`, hid).Scan(&total, &unknown); err != nil {
				return err
			}
			status := "partial"
			if total > 0 && unknown == 0 {
				status = "completed"
			}
			if total == 0 && b.Run.Exit == "success" && h.Scan != nil && !h.Scan.TimedOut {
				status = "not_applicable"
			}
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO run_coverage(run_id,host_id,stage,status) VALUES(?,?,?,?)`, runID, hid, coverage.StageSvcVersion, status); err != nil {
				return err
			}
		}
	}
	if b.Run.Kind == "nuclei" {
		for _, v := range b.Vulns {
			if hid, ok := hostIDs[v.IP]; ok {
				if err := insertCoverage(ctx, tx, runID, hid, coverage.StageVulnScan); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func insertCoverage(ctx context.Context, tx *sql.Tx, runID, hostID int64, stage string) error {
	_, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO run_coverage (run_id, host_id, stage,status) VALUES (?, ?, ?,'completed')`,
		runID, hostID, stage)
	return err
}
