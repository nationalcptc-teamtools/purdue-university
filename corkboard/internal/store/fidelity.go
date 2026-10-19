package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"

	"corkboard/internal/ingest"
	"corkboard/internal/model"
)

func (s *Store) recordScan(ctx context.Context, tx *sql.Tx, runID int64, hostID *int64, h ingest.HostObs, run ingest.RunInfo, now int64) error {
	at := run.ObservedAt(now)
	if h.Scan != nil && h.Scan.At > 0 {
		at = h.Scan.At
	}
	for i := range h.OSEvidence {
		if h.OSEvidence[i].At == 0 {
			h.OSEvidence[i].At = at
		}
	}
	if len(h.OSEvidence) == 0 && h.OS != "" {
		h.OSEvidence = []ingest.OSEvidence{{Name: h.OS, Family: ingest.OSFamily(h.OS), Source: "legacy", Accuracy: h.OSAcc, At: at}}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO scan_evidence(run_id,ip,host_id,vantage,observed_at,run_json,host_json) VALUES(?,?,?,?,?,?,?)`, runID, h.IP, hostID, run.Vantage, at, jsonOr(run), jsonOr(h))
	if err != nil || hostID == nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT host_json FROM scan_evidence WHERE host_id=? ORDER BY observed_at DESC,run_id DESC`, *hostID)
	if err != nil {
		return err
	}
	var evidence []ingest.OSEvidence
	for rows.Next() {
		var data string
		if err = rows.Scan(&data); err != nil {
			break
		}
		var old ingest.HostObs
		if err = json.Unmarshal([]byte(data), &old); err != nil {
			break
		}
		evidence = append(evidence, old.OSEvidence...)
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	sort.SliceStable(evidence, func(i, j int) bool {
		a, b := evidence[i], evidence[j]
		if a.Rank() != b.Rank() {
			return a.Rank() > b.Rank()
		}
		if a.At != b.At {
			return a.At > b.At
		}
		return a.Accuracy > b.Accuracy
	})
	if len(evidence) > 0 {
		best := evidence[0]
		if _, err = tx.ExecContext(ctx, `UPDATE hosts SET os=?,os_accuracy=? WHERE id=?`, best.Name, nullAcc(best.Accuracy), *hostID); err != nil {
			return err
		}
		for key, val := range map[string]string{"os_family": best.Family, "os_source": best.Source, "os_build": best.Build} {
			if _, err = tx.ExecContext(ctx, `INSERT INTO host_attrs(host_id,key,value,source,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(host_id,key) DO UPDATE SET value=excluded.value,source=excluded.source,updated_at=excluded.updated_at`, *hostID, key, val, best.Source, best.At); err != nil {
				return err
			}
		}
	}
	if h.Scan == nil {
		return nil
	}
	return s.reconcilePortStates(ctx, tx, runID, *hostID, h, run, at)
}

func explicitState(h ingest.HostObs, run ingest.RunInfo, proto string, port int) string {
	for _, p := range h.Scan.Ports {
		if p.Proto == proto && p.Port == port {
			return p.State
		}
	}
	if h.Scan.TimedOut || run.Exit != "success" {
		return ""
	}

	var covered map[int]bool
	for _, si := range run.ScanInfo {
		if si.Protocol == proto {
			covered, _ = ingest.ParsePortList(si.Services)
		}
	}
	if !covered[port] {
		return ""
	}
	for _, p := range h.Scan.Ports {
		if p.Proto == proto {
			delete(covered, p.Port)
		}
	}
	for _, e := range h.Scan.Extra {
		if e.Ports != "" && e.Proto == proto {
			ports, err := ingest.ParsePortList(e.Ports)
			if err == nil && len(ports) == e.Count && ports[port] {
				return e.State
			}
		}
	}
	if len(run.ScanInfo) == 1 && len(h.Scan.Extra) == 1 {
		e := h.Scan.Extra[0]
		if e.Count == len(covered) && covered[port] {
			return e.State
		}
	}
	return ""
}

func (s *Store) reconcilePortStates(ctx context.Context, tx *sql.Tx, runID, hid int64, h ingest.HostObs, run ingest.RunInfo, at int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,proto,port,state FROM services WHERE host_id=?`, hid)
	if err != nil {
		return err
	}
	type endpoint struct {
		id    int64
		proto string
		port  int
		state string
	}
	var endpoints []endpoint
	for rows.Next() {
		var e endpoint
		if err = rows.Scan(&e.id, &e.proto, &e.port, &e.state); err != nil {
			break
		}
		endpoints = append(endpoints, e)
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if rowErr != nil {
		return rowErr
	}
	for _, e := range endpoints {
		state := explicitState(h, run, e.proto, e.port)
		if state == "" {
			continue
		}
		method := ""
		conf := 0
		for _, svc := range h.Services {
			if svc.Proto == e.proto && svc.Port == e.port {
				method = svc.Method
				conf = svc.Confidence
			}
		}
		result, writeErr := tx.ExecContext(ctx, `INSERT INTO service_views(host_id,proto,port,vantage,run_id,observed_at,state,method,confidence) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(host_id,proto,port,vantage) DO UPDATE SET run_id=excluded.run_id,observed_at=excluded.observed_at,state=excluded.state,method=CASE WHEN excluded.method='' OR (excluded.method='table' AND service_views.method='probed') THEN service_views.method ELSE excluded.method END,confidence=CASE WHEN excluded.method='' OR (excluded.method='table' AND service_views.method='probed') THEN service_views.confidence ELSE excluded.confidence END WHERE excluded.observed_at>=service_views.observed_at`, hid, e.proto, e.port, run.Vantage, runID, at, state, method, conf)
		if writeErr != nil {
			return writeErr
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			continue
		}

		var open int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM service_views WHERE host_id=? AND proto=? AND port=? AND state IN ('open','open|filtered')`, hid, e.proto, e.port).Scan(&open); err != nil {
			return err
		}
		if open > 0 {
			var definite int
			if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM service_views WHERE host_id=? AND proto=? AND port=? AND state='open'`, hid, e.proto, e.port).Scan(&definite); err != nil {
				return err
			}
			merged := "open|filtered"
			if definite > 0 {
				merged = "open"
			}
			if _, err = tx.ExecContext(ctx, `UPDATE services SET state=? WHERE id=?`, merged, e.id); err != nil {
				return err
			}
		}
		if state == "closed" && open == 0 {
			if _, err = tx.ExecContext(ctx, `UPDATE services SET state='closed',last_seen=MAX(last_seen,?) WHERE id=?`, at, e.id); err != nil {
				return err
			}
			if e.state != "closed" {
				if err = s.observe(ctx, tx, runID, hid, &e.id, "port_closed", jsonOr(map[string]any{"port": e.port, "proto": e.proto, "vantage": run.Vantage}), at); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *Store) ScanHistory(ctx context.Context, ip string) ([]model.ScanRecord, error) {
	q := `SELECT run_id,ip,host_id,vantage,observed_at,run_json,host_json FROM scan_evidence`
	var args []any
	if ip != "" {
		q += ` WHERE ip=?`
		args = append(args, ip)
	}
	q += ` ORDER BY observed_at DESC,run_id DESC`
	rows, err := s.db.Read.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ScanRecord
	for rows.Next() {
		var r model.ScanRecord
		var hid sql.NullInt64
		var run, host string
		if err = rows.Scan(&r.RunID, &r.IP, &hid, &r.Vantage, &r.At, &run, &host); err != nil {
			return nil, err
		}
		if hid.Valid {
			v := hid.Int64
			r.HostID = &v
		}
		if err = json.Unmarshal([]byte(run), &r.Run); err != nil {
			return nil, fmt.Errorf("scan run: %w", err)
		}
		if err = json.Unmarshal([]byte(host), &r.Host); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
