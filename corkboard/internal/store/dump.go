package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"corkboard/internal/model"
)

func (s *Store) DumpAll(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	q := s.db.Read.QueryContext
	targets, err := s.ListBloodHoundTargets(ctx)
	if err != nil {
		return nil, err
	}
	out["bloodhound_targets"] = targets

	{
		rows, err := q(ctx, `SELECT key, value FROM meta ORDER BY key`)
		if err != nil {
			return nil, err
		}
		meta := map[string]string{}
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				rows.Close()
				return nil, err
			}
			meta[k] = v
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out["meta"] = meta
	}

	{
		rows, err := q(ctx, `SELECT id, kind, uploaded_by, uploaded_at, started_at, finished_at,
		       command, source_name, source_sha256, stages, stats,vantage
		       FROM runs ORDER BY id`)
		if err != nil {
			return nil, err
		}
		var runs []map[string]any
		for rows.Next() {
			var id int64
			var kind, uploadedBy, vantage string
			var uploadedAt int64
			var started, finished sql.NullInt64
			var command, sourceName, sha, stages, stats sql.NullString
			if err := rows.Scan(&id, &kind, &uploadedBy, &uploadedAt, &started, &finished,
				&command, &sourceName, &sha, &stages, &stats, &vantage); err != nil {
				rows.Close()
				return nil, err
			}
			stagesV, _ := json.Marshal([]any{})
			if stages.Valid {
				json.Unmarshal([]byte(stages.String), &stagesV)
			}
			statsV := map[string]any{}
			if stats.Valid {
				json.Unmarshal([]byte(stats.String), &statsV)
			}
			runs = append(runs, map[string]any{
				"id": id, "kind": kind, "uploaded_by": uploadedBy,
				"uploaded_at": uploadedAt, "started_at": n64(started),
				"finished_at": n64(finished), "command": nstr(command),
				"source_name": nstr(sourceName), "source_sha256": nstr(sha),
				"stages": stagesV, "stats": statsV, "vantage": vantage,
			})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out["runs"] = runs
	}

	{
		hosts, err := s.ListExportHosts(ctx)
		if err != nil {
			return nil, err
		}
		byID := map[int64]*map[string]any{}
		var hostOut []map[string]any
		for _, h := range hosts {
			m := map[string]any{
				"id": h.ID, "ip": h.IP, "os": h.OS, "os_accuracy": h.OSAccuracy,
				"domain": h.Domain, "mac": h.MAC, "mac_vendor": h.MACVendor,
				"status": h.Status, "scope_zone": h.Zone, "owner": h.Owner,
				"claimed_at": h.ClaimedAt, "priority": h.Priority,
				"first_seen": h.FirstSeen, "last_seen": h.LastSeen,
				"updated_at": h.UpdatedAt,
				"hostnames":  []any{}, "tags": []any{}, "attrs": map[string]string{},
			}
			hostOut = append(hostOut, m)
			byID[h.ID] = &m
		}
		rows, err := q(ctx, `SELECT host_id, name, source, first_seen FROM hostnames ORDER BY host_id, name`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var hid int64
			var name, source string
			var first int64
			if err := rows.Scan(&hid, &name, &source, &first); err != nil {
				rows.Close()
				return nil, err
			}
			if m, ok := byID[hid]; ok {
				(*m)["hostnames"] = append((*m)["hostnames"].([]any), map[string]any{
					"name": name, "source": source, "first_seen": first,
				})
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		rows, err = q(ctx, `SELECT host_id, tag, source FROM host_tags ORDER BY host_id, tag`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var hid int64
			var tag, source string
			if err := rows.Scan(&hid, &tag, &source); err != nil {
				rows.Close()
				return nil, err
			}
			if m, ok := byID[hid]; ok {
				(*m)["tags"] = append((*m)["tags"].([]any), map[string]any{"tag": tag, "source": source})
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		rows, err = q(ctx, `SELECT host_id, key, value, source, updated_at FROM host_attrs ORDER BY host_id, key`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var hid int64
			var k, v, source string
			var at int64
			if err := rows.Scan(&hid, &k, &v, &source, &at); err != nil {
				rows.Close()
				return nil, err
			}
			if m, ok := byID[hid]; ok {
				attrs := (*m)["attrs"].(map[string]string)
				attrs[k] = v
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out["hosts"] = hostOut
	}

	{
		rows, err := q(ctx, `SELECT id, host_id, proto, port, state, name, product, version,
		       extrainfo, tunnel, cpe, first_seen, last_seen
		       FROM services ORDER BY id`)
		if err != nil {
			return nil, err
		}
		type svcOut struct {
			model.Service
			Scripts []model.Script `json:"scripts,omitempty"`
		}
		var svcs []svcOut
		bySvc := map[int64]*svcOut{}
		for rows.Next() {
			var sv svcOut
			var name, product, version, extra, tunnel, cpe sql.NullString
			var osAcc sql.NullInt64
			_ = osAcc
			if err := rows.Scan(&sv.ID, &sv.HostID, &sv.Proto, &sv.Port, &sv.State,
				&name, &product, &version, &extra, &tunnel, &cpe, &sv.FirstSeen, &sv.LastSeen); err != nil {
				rows.Close()
				return nil, err
			}
			sv.Name, sv.Product, sv.Version = name.String, product.String, version.String
			sv.ExtraInfo, sv.Tunnel = extra.String, tunnel.String
			if cpe.Valid {
				json.Unmarshal([]byte(cpe.String), &sv.CPE)
			}
			svcs = append(svcs, sv)
			bySvc[sv.ID] = &svcs[len(svcs)-1]
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		scriptRows, err := q(ctx, `SELECT service_id, host_id, script_id, output, run_id, updated_at
		       FROM service_scripts ORDER BY host_id, script_id`)
		if err != nil {
			return nil, err
		}
		hostScripts := map[int64][]model.Script{}
		for scriptRows.Next() {
			var svcID sql.NullInt64
			var hostID int64
			var id, output string
			var runID, at int64
			if err := scriptRows.Scan(&svcID, &hostID, &id, &output, &runID, &at); err != nil {
				scriptRows.Close()
				return nil, err
			}
			sc := model.Script{ID: id, Output: output}
			if svcID.Valid {
				if sv, ok := bySvc[svcID.Int64]; ok {
					sv.Scripts = append(sv.Scripts, sc)
				}
			} else {
				hostScripts[hostID] = append(hostScripts[hostID], sc)
			}
		}
		scriptRows.Close()
		if err := scriptRows.Err(); err != nil {
			return nil, err
		}
		out["services"] = svcs
		out["host_scripts"] = hostScripts
	}

	{
		rows, err := q(ctx, `SELECT id, run_id, host_id, service_id, what, detail, at
		       FROM observations ORDER BY id`)
		if err != nil {
			return nil, err
		}
		var obs []map[string]any
		for rows.Next() {
			var id, runID, hostID, at int64
			var svcID sql.NullInt64
			var what, detail string
			if err := rows.Scan(&id, &runID, &hostID, &svcID, &what, &detail, &at); err != nil {
				rows.Close()
				return nil, err
			}
			detailV := map[string]any{}
			json.Unmarshal([]byte(detail), &detailV)
			obs = append(obs, map[string]any{
				"id": id, "run_id": runID, "host_id": hostID,
				"service_id": n64i(svcID), "what": what, "detail": detailV, "at": at,
			})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out["observations"] = obs
	}

	{
		rows, err := q(ctx, `SELECT run_id, host_id, stage,status FROM run_coverage ORDER BY run_id, host_id, stage`)
		if err != nil {
			return nil, err
		}
		var cov []map[string]any
		for rows.Next() {
			var runID, hostID int64
			var stage, status string
			if err := rows.Scan(&runID, &hostID, &stage, &status); err != nil {
				rows.Close()
				return nil, err
			}
			cov = append(cov, map[string]any{"run_id": runID, "host_id": hostID, "stage": stage, "status": status})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out["run_coverage"] = cov
	}

	{
		rows, err := q(ctx, `SELECT id, service_id, host_id, url, final_url, status_code, title,
		       technologies, tls_subject, tls_sans, screenshot, thumb, failed,
		       failed_reason, run_id, probed_at
		       FROM web_results ORDER BY id`)
		if err != nil {
			return nil, err
		}
		var webs []map[string]any
		for rows.Next() {
			var id, runID int64
			var svcID, hostID, status, probed sql.NullInt64
			var url, final, title, techs, subject, sans, shot, thumb, reason sql.NullString
			var failed int
			if err := rows.Scan(&id, &svcID, &hostID, &url, &final, &status, &title,
				&techs, &subject, &sans, &shot, &thumb, &failed, &reason, &runID, &probed); err != nil {
				rows.Close()
				return nil, err
			}
			techsV := []string{}
			if techs.Valid {
				json.Unmarshal([]byte(techs.String), &techsV)
			}
			sansV := []string{}
			if sans.Valid {
				json.Unmarshal([]byte(sans.String), &sansV)
			}
			webs = append(webs, map[string]any{
				"id": id, "service_id": n64i(svcID), "host_id": n64i(hostID),
				"url": url.String, "final_url": nstr(final), "status_code": n64(status),
				"title": nstr(title), "technologies": techsV, "tls_subject": nstr(subject),
				"tls_sans": sansV, "screenshot": nstr(shot), "thumb": nstr(thumb),
				"failed": failed != 0, "failed_reason": nstr(reason),
				"run_id": runID, "probed_at": n64(probed),
			})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out["web_results"] = webs
	}

	{
		creds, err := s.ListCreds(ctx)
		if err != nil {
			return nil, err
		}
		out["creds"] = creds
	}

	{
		rows, err := q(ctx, `SELECT id, host_id, name, remark, cred_id, can_read, can_write, observed_at
		       FROM shares ORDER BY id`)
		if err != nil {
			return nil, err
		}
		var shares []map[string]any
		for rows.Next() {
			var id, hostID, at int64
			var credID sql.NullInt64
			var name, remark sql.NullString
			var r, w int
			if err := rows.Scan(&id, &hostID, &name, &remark, &credID, &r, &w, &at); err != nil {
				rows.Close()
				return nil, err
			}
			shares = append(shares, map[string]any{
				"id": id, "host_id": hostID, "name": name.String, "remark": nstr(remark),
				"cred_id": n64i(credID), "can_read": r != 0, "can_write": w != 0,
				"observed_at": at,
			})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out["shares"] = shares
	}

	{
		tasks, err := s.ListTasks(ctx, TaskFilter{})
		if err != nil {
			return nil, err
		}
		out["tasks"] = tasks
	}
	{
		notes, err := s.ListNotes(ctx)
		if err != nil {
			return nil, err
		}
		out["notes"] = notes
	}
	{
		comps, err := s.ListCompromises(ctx)
		if err != nil {
			return nil, err
		}
		out["compromises"] = comps
	}
	{
		findings, err := s.ListFindings(ctx, FindingFilter{})
		if err != nil {
			return nil, err
		}
		out["findings"] = findings
	}
	{
		rows, err := q(ctx, `SELECT id, actor, at, kind, host_id, ref_id, summary, data
		       FROM events ORDER BY id`)
		if err != nil {
			return nil, err
		}
		var events []map[string]any
		for rows.Next() {
			var id, at int64
			var actor, kind, summary, data string
			var hostID, refID sql.NullInt64
			if err := rows.Scan(&id, &actor, &at, &kind, &hostID, &refID, &summary, &data); err != nil {
				rows.Close()
				return nil, err
			}
			dataV := map[string]any{}
			json.Unmarshal([]byte(data), &dataV)
			events = append(events, map[string]any{
				"id": id, "actor": actor, "at": at, "kind": kind,
				"host_id": n64i(hostID), "ref_id": n64i(refID),
				"summary": summary, "data": dataV,
			})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out["events"] = events
	}
	{
		rows, err := q(ctx, `SELECT key, at FROM alerts_sent ORDER BY key`)
		if err != nil {
			return nil, err
		}
		var alerts []map[string]any
		for rows.Next() {
			var k string
			var at int64
			if err := rows.Scan(&k, &at); err != nil {
				rows.Close()
				return nil, err
			}
			alerts = append(alerts, map[string]any{
				"key": k, "at": at,
			})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out["alerts_sent"] = alerts
	}
	scans, err := s.ScanHistory(ctx, "")
	if err != nil {
		return nil, err
	}
	out["scan_evidence"] = scans
	return out, nil
}

func n64(v sql.NullInt64) any {
	if v.Valid {
		return v.Int64
	}
	return nil
}

func n64i(v sql.NullInt64) any {
	if v.Valid {
		return v.Int64
	}
	return nil
}

func nstr(v sql.NullString) any {
	if v.Valid {
		return v.String
	}
	return nil
}

var _ = fmt.Sprintf
