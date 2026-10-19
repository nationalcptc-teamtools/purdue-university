package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type CheckFilter struct {
	CredID        int64
	Target        *TargetRef
	Vantage       string
	State         string
	Applicability string
	Limit, Offset int
}
type CheckKey struct {
	CredID     int64 `json:"cred_id"`
	EndpointID int64 `json:"endpoint_id"`
	Generation int64 `json:"generation"`
}
type CheckRow struct {
	CheckKey
	Identity          string    `json:"identity"`
	SecretType        string    `json:"secret_type"`
	TargetID          int64     `json:"target_id"`
	Target            TargetRef `json:"target"`
	HostID            *int64    `json:"host_id"`
	Label             string    `json:"label"`
	Protocol          string    `json:"protocol"`
	Vantage           string    `json:"vantage"`
	Applicability     string    `json:"applicability"`
	State             string    `json:"state"`
	Owner             string    `json:"owner"`
	Reason            string    `json:"reason"`
	CurrentResult     string    `json:"current_result"`
	CurrentOccurredAt *int64    `json:"current_occurred_at"`
	CurrentRecordedAt *int64    `json:"current_recorded_at"`
	WorkID            int64     `json:"work_id"`
}
type CheckSummary struct {
	Known   int64 `json:"known"`
	Checked int64 `json:"checked"`
	Waived  int64 `json:"waived"`
	Pending int64 `json:"pending"`
	Unknown int64 `json:"unknown"`
	Done    bool  `json:"done"`
}
type CheckPage struct {
	Rows    []CheckRow   `json:"rows"`
	Summary CheckSummary `json:"summary"`
	More    bool         `json:"more"`
}

func checkWhere(f CheckFilter) (string, []any, error) {

	where := " WHERE applicability<>'excluded' AND (host_id IS NULL OR host_id NOT IN (SELECT id FROM hosts WHERE status='locked'))"
	var args []any
	if f.CredID > 0 {
		where += " AND cred_id=?"
		args = append(args, f.CredID)
	}
	if f.Target != nil {
		switch f.Target.Kind {
		case "host":
			where += " AND host_id=?"
			args = append(args, f.Target.ID)
		case "service", "application":
			where += " AND kind=? AND ref_id=?"
			args = append(args, f.Target.Kind, f.Target.ID)
		default:
			return "", nil, fmt.Errorf("checks require a host, service, or application")
		}
	}
	if f.Vantage != "*" {
		where += " AND vantage=?"
		args = append(args, f.Vantage)
	}
	return where, args, nil
}
func (s *Store) Checks(ctx context.Context, f CheckFilter) (CheckPage, error) {
	page := CheckPage{Rows: []CheckRow{}}
	where, args, err := checkWhere(f)
	if err != nil {
		return page, err
	}
	err = s.db.Read.QueryRowContext(ctx, `SELECT COALESCE(SUM(applicability='eligible'),0),COALESCE(SUM(applicability='eligible' AND state='completed'),0),COALESCE(SUM(applicability='eligible' AND state='waived'),0),COALESCE(SUM(applicability='eligible' AND state IN ('pending','claimed','blocked')),0),COALESCE(SUM(applicability='unknown'),0) FROM credential_pairs`+where, args...).Scan(&page.Summary.Known, &page.Summary.Checked, &page.Summary.Waived, &page.Summary.Pending, &page.Summary.Unknown)
	if err != nil {
		return page, err
	}
	page.Summary.Done = page.Summary.Known > 0 && page.Summary.Pending == 0 && page.Summary.Unknown == 0
	if f.State != "" {
		switch f.State {
		case "pending", "claimed", "blocked", "completed", "waived":
		default:
			return page, fmt.Errorf("invalid check state")
		}
		where += " AND state=?"
		args = append(args, f.State)
	}
	if f.Applicability != "" {
		if f.Applicability != "eligible" && f.Applicability != "unknown" {
			return page, fmt.Errorf("invalid applicability filter")
		}
		where += " AND applicability=?"
		args = append(args, f.Applicability)
	}
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 200 {
		f.Limit = 200
	}
	if f.Offset < 0 {
		return page, fmt.Errorf("invalid offset")
	}
	args = append(args, f.Limit+1, f.Offset)
	rows, err := s.db.Read.QueryContext(ctx, `SELECT cred_id,endpoint_id,generation,identity,secret_type,target_id,kind,ref_id,host_id,label,protocol,vantage,applicability,state,owner,reason,current_result,current_occurred_at,current_recorded_at,work_id FROM credential_pairs`+where+` ORDER BY CASE applicability WHEN 'unknown' THEN 1 ELSE 0 END,CASE state WHEN 'pending' THEN 0 WHEN 'blocked' THEN 1 WHEN 'claimed' THEN 2 ELSE 3 END,changed_at DESC,cred_id,endpoint_id LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var r CheckRow
		if err = rows.Scan(&r.CredID, &r.EndpointID, &r.Generation, &r.Identity, &r.SecretType, &r.TargetID, &r.Target.Kind, &r.Target.ID, &r.HostID, &r.Label, &r.Protocol, &r.Vantage, &r.Applicability, &r.State, &r.Owner, &r.Reason, &r.CurrentResult, &r.CurrentOccurredAt, &r.CurrentRecordedAt, &r.WorkID); err != nil {
			return page, err
		}
		page.Rows = append(page.Rows, r)
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	if len(page.Rows) > f.Limit {
		page.More = true
		page.Rows = page.Rows[:f.Limit]
	}
	return page, nil
}
func ensureCheckWork(ctx context.Context, tx *sql.Tx, k CheckKey, now int64, requireEligible bool) (int64, error) {
	var gen int64
	var state string
	if err := tx.QueryRowContext(ctx, "SELECT generation,state FROM auth_endpoints WHERE id=?", k.EndpointID).Scan(&gen, &state); err != nil {
		return 0, err
	}
	if gen != k.Generation || state != "open" {
		return 0, fmt.Errorf("endpoint generation/state changed; refresh the queue")
	}
	if requireEligible {
		var decision string
		if err := tx.QueryRowContext(ctx, "SELECT applicability FROM credential_pairs WHERE cred_id=? AND endpoint_id=?", k.CredID, k.EndpointID).Scan(&decision); err != nil {
			return 0, fmt.Errorf("inactive or incompatible credential/endpoint")
		}
		if decision != "eligible" {
			return 0, fmt.Errorf("applicability requires review")
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO check_work(cred_id,endpoint_id,generation,updated_at) VALUES(?,?,?,?)`, k.CredID, k.EndpointID, k.Generation, now); err != nil {
		return 0, err
	}
	var id int64
	err := tx.QueryRowContext(ctx, `SELECT id FROM check_work WHERE cred_id=? AND endpoint_id=? AND generation=?`, k.CredID, k.EndpointID, k.Generation).Scan(&id)
	return id, err
}

type CheckAction struct {
	Keys          []CheckKey `json:"keys"`
	Action        string     `json:"action"`
	Reason        string     `json:"reason"`
	ExpectedOwner string     `json:"expected_owner"`
}

func (s *Store) CheckAction(ctx context.Context, user string, in CheckAction) error {
	if len(in.Keys) == 0 || len(in.Keys) > 1000 {
		return fmt.Errorf("choose 1–1000 checks")
	}
	if (in.Action == "recheck" || in.Action == "waive" || in.Action == "block") && strings.TrimSpace(in.Reason) == "" {
		return fmt.Errorf("reason required")
	}
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		for _, k := range in.Keys {
			id, err := ensureCheckWork(ctx, tx, k, s.nowMS(), true)
			if err != nil {
				return err
			}
			var owner, state string
			if err = tx.QueryRowContext(ctx, "SELECT owner,state FROM check_work WHERE id=?", id).Scan(&owner, &state); err != nil {
				return err
			}
			next := state
			newOwner := owner
			switch in.Action {
			case "claim":
				var status string
				err = tx.QueryRowContext(ctx, `SELECT h.status FROM credential_pairs cp JOIN hosts h ON h.id=cp.host_id WHERE cp.cred_id=? AND cp.endpoint_id=? LIMIT 1`, k.CredID, k.EndpointID).Scan(&status)
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return err
				}
				if status == "locked" {
					return ErrHostLocked
				}
				if owner != "" && owner != user && owner != in.ExpectedOwner {
					return fmt.Errorf("check claimed by %s", owner)
				}
				if state == "completed" || state == "waived" {
					return fmt.Errorf("reopen the check before claiming it")
				}
				next = "claimed"
				newOwner = user
			case "release":
				if owner != user {
					return ErrNotOwner
				}
				next = "pending"
				newOwner = ""
			case "recheck":
				next = "pending"
				newOwner = ""
			case "waive":
				next = "waived"
				newOwner = ""
			case "block":
				next = "blocked"
			default:
				return fmt.Errorf("invalid check action")
			}
			if _, err = tx.ExecContext(ctx, "UPDATE check_work SET state=?,owner=?,reason=?,updated_at=? WHERE id=?", next, newOwner, in.Reason, s.nowMS(), id); err != nil {
				return err
			}
			if in.Action == "recheck" || in.Action == "waive" {
				result := "recheck"
				if in.Action == "waive" {
					result = "waived"
				}
				if _, err = tx.ExecContext(ctx, `INSERT INTO check_results(work_id,result,actor,recorded_at,source,detail) VALUES(?,?,?,?,?,?)`, id, result, user, s.nowMS(), "manual", in.Reason); err != nil {
					return err
				}
			}
			if err = s.appendEvent(ctx, tx, s.nowMS(), user, "check_"+in.Action, nil, &id, in.Reason, jsonOr(k)); err != nil {
				return err
			}
		}
		return nil
	})
}

type CheckResultInput struct {
	CheckKey
	Result        string `json:"result"`
	OccurredAt    *int64 `json:"occurred_at"`
	Detail        string `json:"detail"`
	ConfirmedLoss bool   `json:"confirmed_loss"`
}

func (s *Store) RecordCheck(ctx context.Context, user string, in CheckResultInput) (int64, error) {
	var id int64
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var err error
		id, err = s.recordCheck(ctx, tx, user, in, "manual", nil, true)
		return err
	})
	return id, err
}
func (s *Store) recordCheck(ctx context.Context, tx *sql.Tx, user string, in CheckResultInput, source string, runID *int64, requireEligible bool) (int64, error) {
	if in.Result != "invalid" && in.Result != "valid" && in.Result != "admin" && in.Result != "inconclusive" {
		return 0, fmt.Errorf("result must be invalid, valid, admin, or inconclusive")
	}
	if in.ConfirmedLoss && in.Result != "invalid" {
		return 0, fmt.Errorf("confirmed loss requires an invalid revalidation")
	}
	if len(in.Detail) > 8192 {
		return 0, fmt.Errorf("result detail exceeds 8 KiB")
	}
	now := s.nowMS()
	work, err := ensureCheckWork(ctx, tx, in.CheckKey, now, requireEligible)
	if err != nil {
		return 0, err
	}
	var oldAt *int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(r.occurred_at,r.recorded_at) FROM check_work w LEFT JOIN check_results r ON r.id=w.current_result_id WHERE w.id=?`, work).Scan(&oldAt); err != nil {
		return 0, err
	}
	at := now
	if in.OccurredAt != nil {
		at = *in.OccurredAt
	}
	definitive := in.Result != "inconclusive" && (oldAt == nil || at >= *oldAt)

	if source != "manual" && in.OccurredAt == nil {
		definitive = false
	}
	var changedAt int64
	if err = tx.QueryRowContext(ctx, "SELECT changed_at FROM auth_endpoints WHERE id=?", in.EndpointID).Scan(&changedAt); err != nil {
		return 0, err
	}
	if in.OccurredAt != nil && *in.OccurredAt < changedAt {
		definitive = false
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO check_results(work_id,result,actor,occurred_at,recorded_at,source,run_id,accepted_current,confirmed_loss,detail) VALUES(?,?,?,?,?,?,?,?,?,?)`, work, in.Result, user, in.OccurredAt, now, source, runID, definitive, in.ConfirmedLoss, in.Detail)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	if definitive {
		if _, err = tx.ExecContext(ctx, `UPDATE check_work SET state='completed',owner='',current_result_id=?,updated_at=? WHERE id=?`, id, now, work); err != nil {
			return 0, err
		}
	} else if in.Result == "inconclusive" && (oldAt == nil || at >= *oldAt) {
		if _, err = tx.ExecContext(ctx, `UPDATE check_work SET state='blocked',reason=?,updated_at=? WHERE id=?`, in.Detail, now, work); err != nil {
			return 0, err
		}
	}
	var hid *int64
	var ip, protocol string
	if err = tx.QueryRowContext(ctx, `SELECT t.host_id,COALESCE(h.ip,''),e.protocol FROM auth_endpoints e JOIN target_details t ON t.id=e.target_id LEFT JOIN hosts h ON h.id=t.host_id WHERE e.id=?`, in.EndpointID).Scan(&hid, &ip, &protocol); err != nil {
		return 0, err
	}
	if hid != nil && in.Result != "inconclusive" {
		if err = s.mergeAccessOneByID(ctx, tx, in.CredID, *hid, ip, protocol, in.Result, source, now); err != nil {
			return 0, err
		}
	}
	if err = s.appendEvent(ctx, tx, now, user, "check_result", hid, &id, "credential check: "+in.Result, jsonOr(map[string]any{"cred_id": in.CredID, "endpoint_id": in.EndpointID, "generation": in.Generation, "occurred_at": in.OccurredAt, "accepted_current": definitive, "confirmed_loss": in.ConfirmedLoss})); err != nil {
		return 0, err
	}
	return id, nil
}

type CheckResult struct {
	ID              int64  `json:"id"`
	WorkID          int64  `json:"work_id"`
	Result          string `json:"result"`
	Actor           string `json:"actor"`
	OccurredAt      *int64 `json:"occurred_at"`
	RecordedAt      int64  `json:"recorded_at"`
	Source          string `json:"source"`
	AcceptedCurrent bool   `json:"accepted_current"`
	ConfirmedLoss   bool   `json:"confirmed_loss"`
	Detail          string `json:"detail"`
}

func (s *Store) CheckHistory(ctx context.Context, cred, endpoint int64) ([]CheckResult, error) {
	rows, err := s.db.Read.QueryContext(ctx, `SELECT r.id,r.work_id,r.result,r.actor,r.occurred_at,r.recorded_at,r.source,r.accepted_current,r.confirmed_loss,r.detail FROM check_results r JOIN check_work w ON w.id=r.work_id WHERE w.cred_id=? AND w.endpoint_id=? ORDER BY r.id DESC LIMIT 500`, cred, endpoint)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CheckResult{}
	for rows.Next() {
		var r CheckResult
		if err = rows.Scan(&r.ID, &r.WorkID, &r.Result, &r.Actor, &r.OccurredAt, &r.RecordedAt, &r.Source, &r.AcceptedCurrent, &r.ConfirmedLoss, &r.Detail); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) CredentialProfiles(ctx context.Context) ([]CredentialProfile, error) {
	rows, err := s.db.Read.QueryContext(ctx, `SELECT p.cred_id,c.domain||CASE WHEN c.domain='' THEN '' ELSE '\' END||c.username,c.secret_type,p.retired,p.scope_kind,p.scope_value,p.protocols,p.revision_of,p.cracked_from FROM credential_profiles p JOIN creds c ON c.id=p.cred_id ORDER BY p.cred_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CredentialProfile{}
	for rows.Next() {
		var p CredentialProfile
		var protocols string
		if err = rows.Scan(&p.CredID, &p.Identity, &p.SecretType, &p.Retired, &p.ScopeKind, &p.ScopeValue, &protocols, &p.RevisionOf, &p.CrackedFrom); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(protocols), &p.Protocols); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
