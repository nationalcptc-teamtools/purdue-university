package store

import (
	"context"
	"database/sql"
	"fmt"
)

func (s *Store) recordAccessObservation(ctx context.Context, tx *sql.Tx, user string, cred, hid int64, protocol, result, vantage, source string, runID *int64, occurred *int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT e.id,e.generation FROM auth_endpoints e JOIN target_details t ON t.id=e.target_id WHERE t.host_id=? AND e.protocol=? AND e.vantage=? AND e.state='open' ORDER BY e.id`, hid, protocol, vantage)
	if err != nil {
		return err
	}
	var ids, gens []int64
	for rows.Next() {
		var id, gen int64
		if err = rows.Scan(&id, &gen); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
		gens = append(gens, gen)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var endpoint *int64
	reason := "endpoint association required"
	if len(ids) == 1 {
		endpoint = &ids[0]
		reason = "unambiguous endpoint; unknown-time imports remain historical"
	} else if len(ids) > 1 {
		reason = "multiple endpoints match host/protocol"
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO access_observations(cred_id,host_id,protocol,result,vantage,endpoint_id,occurred_at,recorded_at,actor,source,run_id,association_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, cred, hid, protocol, result, vantage, endpoint, occurred, s.nowMS(), user, source, runID, reason); err != nil {
		return err
	}
	if endpoint != nil {
		var changed int64
		if err = tx.QueryRowContext(ctx, "SELECT changed_at FROM auth_endpoints WHERE id=?", *endpoint).Scan(&changed); err != nil {
			return err
		}
		fresh := (source == "manual" && occurred == nil) || (occurred != nil && *occurred >= changed)
		if !fresh {
			return nil
		}
		_, err = s.recordCheck(ctx, tx, user, CheckResultInput{CheckKey: CheckKey{cred, *endpoint, gens[0]}, Result: result, OccurredAt: occurred, Detail: reason}, source, runID, false)
	}
	return err
}
func (s *Store) AccessObservations(ctx context.Context, cred int64) ([]map[string]any, error) {
	rows, err := s.db.Read.QueryContext(ctx, `SELECT o.id,o.cred_id,h.ip,o.protocol,o.result,o.vantage,o.endpoint_id,o.occurred_at,o.recorded_at,o.association_reason FROM access_observations o JOIN hosts h ON h.id=o.host_id WHERE (?=0 OR o.cred_id=?) ORDER BY o.id DESC LIMIT 200`, cred, cred)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, cid, recorded int64
		var ip, protocol, result, vantage, reason string
		var endpoint, occurred *int64
		if err = rows.Scan(&id, &cid, &ip, &protocol, &result, &vantage, &endpoint, &occurred, &recorded, &reason); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "cred_id": cid, "host": ip, "protocol": protocol, "result": result, "vantage": vantage, "endpoint_id": endpoint, "occurred_at": occurred, "recorded_at": recorded, "reason": reason})
	}
	return out, rows.Err()
}
func (s *Store) AssociateObservation(ctx context.Context, user string, observation, endpoint int64, reason string) error {
	if reason == "" {
		return fmt.Errorf("association reason required")
	}
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var hid int64
		var protocol string
		if err := tx.QueryRowContext(ctx, "SELECT host_id,protocol FROM access_observations WHERE id=?", observation).Scan(&hid, &protocol); err != nil {
			return err
		}
		var matched int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_endpoints e JOIN target_details t ON t.id=e.target_id WHERE e.id=? AND e.protocol=? AND t.host_id=?`, endpoint, protocol, hid).Scan(&matched); err != nil {
			return err
		}
		if matched != 1 {
			return fmt.Errorf("endpoint does not match observation host/protocol")
		}
		if _, err := tx.ExecContext(ctx, "UPDATE access_observations SET endpoint_id=?,association_reason=? WHERE id=?", endpoint, reason, observation); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, s.nowMS(), user, "access_association", &hid, &observation, reason, jsonOr(map[string]int64{"endpoint_id": endpoint}))
	})
}
