package store

import (
	"context"
	"corkboard/internal/model"
	"database/sql"
	"fmt"
	"strings"
)

type FindingAsset struct {
	Target
	Evidence    string `json:"evidence"`
	NeedsReview bool   `json:"needs_review"`
}
type History struct {
	ID         int64  `json:"id"`
	Actor      string `json:"actor"`
	OccurredAt *int64 `json:"occurred_at"`
	RecordedAt int64  `json:"recorded_at"`
	Action     string `json:"action"`
	Detail     string `json:"detail"`
}
type Evidence struct {
	ID          int64  `json:"id"`
	SHA         string `json:"sha"`
	MediaType   string `json:"media_type"`
	Caption     string `json:"caption"`
	ExternalRef string `json:"external_ref"`
	Actor       string `json:"actor"`
	OccurredAt  *int64 `json:"occurred_at"`
	RecordedAt  int64  `json:"recorded_at"`
	RunID       *int64 `json:"run_id"`
}
type FindingDetail struct {
	model.Finding
	MergedInto   *int64         `json:"merged_into,omitempty"`
	ReportRef    string         `json:"report_ref"`
	ReportUpdate bool           `json:"report_update"`
	Assets       []FindingAsset `json:"assets"`
	History      []History      `json:"history"`
	Evidence     []Evidence     `json:"evidence"`
}
type FindingInput struct {
	Title         string      `json:"title"`
	Severity      string      `json:"severity"`
	Description   string      `json:"description"`
	State         string      `json:"state"`
	Reason        string      `json:"reason"`
	ReportRef     string      `json:"report_ref"`
	GWTitle       string      `json:"gw_title"`
	Targets       []TargetRef `json:"targets"`
	RemoveTargets []TargetRef `json:"remove_targets"`
	Evidence      string      `json:"evidence"`
	OccurredAt    *int64      `json:"occurred_at"`
	MergeInto     int64       `json:"merge_into"`
}

func (s *Store) findingHistory(ctx context.Context, tx *sql.Tx, id int64, user, action string, input any, occurred *int64) error {
	now := s.nowMS()
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_history(finding_id,actor,occurred_at,recorded_at,action,detail) VALUES(?,?,?,?,?,?)`, id, user, occurred, now, action, jsonOr(input)); err != nil {
		return err
	}
	return s.appendEvent(ctx, tx, now, user, "finding_"+action, nil, &id, fmt.Sprintf("finding %d: %s", id, action), jsonOr(map[string]any{"occurred_at": occurred}))
}
func resolveFindingTx(ctx context.Context, tx *sql.Tx, id int64) (int64, error) {
	for n := 0; n < 32; n++ {
		var merged *int64
		if err := tx.QueryRowContext(ctx, "SELECT merged_into FROM findings WHERE id=?", id).Scan(&merged); err != nil {
			return 0, err
		}
		if merged == nil {
			return id, nil
		}
		id = *merged
	}
	return 0, fmt.Errorf("finding merge chain too long")
}
func (s *Store) CreateFinding(ctx context.Context, user string, in FindingInput) (int64, error) {
	if strings.TrimSpace(in.Title) == "" || !validSeverity[in.Severity] || len(in.Title) > 512 || len(in.Description) > 65536 || len(in.Targets) == 0 || len(in.Evidence) > 2048 {
		return 0, fmt.Errorf("title, severity and affected targets required; evidence max 2 KiB")
	}
	if in.State == "" {
		in.State = "candidate"
	}
	if in.State != "candidate" && in.State != "confirmed" {
		return 0, fmt.Errorf("new findings start candidate or confirmed")
	}
	var id int64
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		now := s.nowMS()
		res, err := tx.ExecContext(ctx, `INSERT INTO findings(dedupe_key,title,severity,source,state,description,created_at,updated_at,operator_edited) VALUES(lower(hex(randomblob(16))),?,?,'manual',?,?,?,?,1)`, in.Title, in.Severity, in.State, in.Description, now, now)
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		if err != nil {
			return err
		}
		for _, target := range in.Targets {
			tid, err := targetTx(ctx, tx, target)
			if err != nil {
				return err
			}
			if err = s.linkFindingTarget(ctx, tx, id, tid, in.Evidence, in.State != "confirmed"); err != nil {
				return err
			}
		}
		return s.findingHistory(ctx, tx, id, user, "created", in, in.OccurredAt)
	})
	return id, err
}
func (s *Store) linkFindingTarget(ctx context.Context, tx *sql.Tx, id, tid int64, evidence string, review bool) error {
	if len(evidence) > 2048 {
		evidence = evidence[:2048-len(" [truncated]")] + " [truncated]"
	}
	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO finding_assets(finding_id,target_id,evidence,needs_review) VALUES(?,?,?,?)`, id, tid, evidence, review)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	var hid, sid *int64
	if err = tx.QueryRowContext(ctx, `SELECT host_id,service_id FROM target_details WHERE id=?`, tid).Scan(&hid, &sid); err != nil {
		return err
	}
	if hid != nil {
		if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO finding_hosts(finding_id,host_id,service_id,evidence) VALUES(?,?,?,?)`, id, hid, sid, evidence); err != nil {
			return err
		}
	}
	if n > 0 {
		if _, err = tx.ExecContext(ctx, `UPDATE findings SET report_update=CASE WHEN state='reported' THEN 1 ELSE report_update END WHERE id=?`, id); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) EditFinding(ctx context.Context, user string, id int64, in FindingInput) error {
	if in.State != "" && !validFindingState[in.State] {
		return fmt.Errorf("invalid finding state")
	}
	if in.Severity != "" && !validSeverity[in.Severity] {
		return fmt.Errorf("invalid severity")
	}
	if in.State == "rejected" && strings.TrimSpace(in.Reason) == "" {
		return fmt.Errorf("rejection requires a reason")
	}
	if len(in.Title) > 512 || len(in.Description) > 65536 || len(in.Evidence) > 2048 {
		return fmt.Errorf("finding text exceeds limit")
	}
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		resolved, err := resolveFindingTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if resolved != id {
			return fmt.Errorf("finding merged into %d", resolved)
		}
		if in.MergeInto > 0 {
			dest, err := resolveFindingTx(ctx, tx, in.MergeInto)
			if err != nil {
				return err
			}
			if dest == id {
				return fmt.Errorf("cannot merge finding into itself")
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO finding_assets SELECT ?,target_id,evidence,1 FROM finding_assets WHERE finding_id=? ON CONFLICT(finding_id,target_id) DO UPDATE SET evidence=substr(finding_assets.evidence||char(10)||excluded.evidence,1,2048),needs_review=1`, dest, id); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO finding_hosts(finding_id,host_id,service_id,evidence) SELECT ?,host_id,service_id,evidence FROM finding_hosts WHERE finding_id=?`, dest, id); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO evidence_links(evidence_id,finding_id,target_id) SELECT evidence_id,?,target_id FROM evidence_links WHERE finding_id=?`, dest, id); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE findings SET merged_into=?,updated_at=? WHERE id=?`, dest, s.nowMS(), id); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE findings SET report_update=CASE WHEN state='reported' THEN 1 ELSE report_update END WHERE id=?`, dest); err != nil {
				return err
			}
			if err = s.findingHistory(ctx, tx, dest, user, "merged", map[string]any{"alias": id}, in.OccurredAt); err != nil {
				return err
			}
			return s.findingHistory(ctx, tx, id, user, "merged", in, in.OccurredAt)
		}
		var before FindingInput
		if err = tx.QueryRowContext(ctx, `SELECT title,severity,description,state,report_ref FROM findings WHERE id=?`, id).Scan(&before.Title, &before.Severity, &before.Description, &before.State, &before.ReportRef); err != nil {
			return err
		}
		for col, val := range map[string]string{"title": in.Title, "severity": in.Severity, "description": in.Description, "state": in.State, "report_ref": in.ReportRef, "gw_library_title": in.GWTitle} {
			if val != "" {
				if _, err = tx.ExecContext(ctx, "UPDATE findings SET "+col+"=?,operator_edited=1,updated_at=? WHERE id=?", val, s.nowMS(), id); err != nil {
					return err
				}
			}
		}
		for _, target := range in.Targets {
			tid, err := targetTx(ctx, tx, target)
			if err != nil {
				return err
			}
			if err = s.linkFindingTarget(ctx, tx, id, tid, in.Evidence, true); err != nil {
				return err
			}
		}
		for _, ref := range in.RemoveTargets {
			tid, err := targetTx(ctx, tx, ref)
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "DELETE FROM finding_assets WHERE finding_id=? AND target_id=?", id, tid); err != nil {
				return err
			}
		}
		if len(in.RemoveTargets) > 0 {
			if _, err = tx.ExecContext(ctx, `DELETE FROM finding_hosts WHERE finding_id=? AND NOT EXISTS(SELECT 1 FROM finding_assets a JOIN target_details t ON t.id=a.target_id WHERE a.finding_id=finding_hosts.finding_id AND t.host_id=finding_hosts.host_id AND t.service_id IS finding_hosts.service_id)`, id); err != nil {
				return err
			}
		}
		if in.State == "confirmed" || in.State == "reported" {
			if _, err = tx.ExecContext(ctx, `UPDATE finding_assets SET needs_review=0 WHERE finding_id=?`, id); err != nil {
				return err
			}
			if in.State == "reported" {
				if _, err = tx.ExecContext(ctx, "UPDATE findings SET report_update=0 WHERE id=?", id); err != nil {
					return err
				}
			}
		}
		return s.findingHistory(ctx, tx, id, user, "updated", map[string]any{"before": before, "change": in}, in.OccurredAt)
	})
}
func (s *Store) FindingDetail(ctx context.Context, id int64) (*FindingDetail, error) {
	d := &FindingDetail{}
	f := &d.Finding
	err := s.db.Read.QueryRowContext(ctx, `SELECT id,dedupe_key,title,severity,source,state,COALESCE(gw_library_title,''),description,created_at,updated_at,merged_into,report_ref,report_update FROM findings WHERE id=?`, id).Scan(&f.ID, &f.DedupeKey, &f.Title, &f.Severity, &f.Source, &f.State, &f.GWLibraryTitle, &f.Description, &f.CreatedAt, &f.UpdatedAt, &d.MergedInto, &d.ReportRef, &d.ReportUpdate)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Read.QueryContext(ctx, `SELECT t.id,t.kind,t.ref_id,t.host_id,t.service_id,t.label,a.evidence,a.needs_review FROM finding_assets a JOIN target_details t ON t.id=a.target_id WHERE a.finding_id=? ORDER BY t.id`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a FindingAsset
		if err = rows.Scan(&a.ID, &a.Kind, &a.RefID, &a.HostID, &a.ServiceID, &a.Label, &a.Evidence, &a.NeedsReview); err != nil {
			rows.Close()
			return nil, err
		}
		d.Assets = append(d.Assets, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	fs := []model.Finding{*f}
	if err = s.attachFindingHosts(ctx, fs, []int64{id}); err != nil {
		return nil, err
	}
	d.Hosts = fs[0].Hosts
	rows, err = s.db.Read.QueryContext(ctx, `SELECT id,actor,occurred_at,recorded_at,action,detail FROM finding_history WHERE finding_id=? ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var h History
		if err = rows.Scan(&h.ID, &h.Actor, &h.OccurredAt, &h.RecordedAt, &h.Action, &h.Detail); err != nil {
			rows.Close()
			return nil, err
		}
		d.History = append(d.History, h)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = s.db.Read.QueryContext(ctx, `SELECT e.id,e.sha,e.media_type,e.caption,e.external_ref,e.actor,e.occurred_at,e.recorded_at,e.run_id FROM evidence e JOIN evidence_links l ON l.evidence_id=e.id WHERE l.finding_id=? ORDER BY e.id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e Evidence
		if err = rows.Scan(&e.ID, &e.SHA, &e.MediaType, &e.Caption, &e.ExternalRef, &e.Actor, &e.OccurredAt, &e.RecordedAt, &e.RunID); err != nil {
			return nil, err
		}
		d.Evidence = append(d.Evidence, e)
	}
	return d, rows.Err()
}
func (s *Store) AddEvidence(ctx context.Context, user string, fid int64, ref TargetRef, e Evidence) (int64, error) {
	if len(e.Caption) > 2048 || len(e.ExternalRef) > 2048 {
		return 0, fmt.Errorf("evidence caption/reference exceeds 2 KiB")
	}
	if e.MediaType != "image/png" && e.MediaType != "image/jpeg" && e.MediaType != "text/plain" && e.MediaType != "external" {
		return 0, fmt.Errorf("unsupported evidence type")
	}
	if e.MediaType == "external" {
		if strings.TrimSpace(e.ExternalRef) == "" {
			return 0, fmt.Errorf("external reference required")
		}
	} else if len(e.SHA) != 64 {
		return 0, fmt.Errorf("invalid evidence hash")
	}
	var id int64
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var target *int64
		if ref.ID != 0 {
			n, err := targetTx(ctx, tx, ref)
			if err != nil {
				return err
			}
			target = &n
		}
		var finding *int64
		if fid > 0 {
			n, err := resolveFindingTx(ctx, tx, fid)
			if err != nil {
				return err
			}
			finding = &n
		}
		if target == nil && finding == nil {
			return fmt.Errorf("evidence must link to a finding or target")
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO evidence(sha,media_type,caption,external_ref,actor,occurred_at,recorded_at,run_id) VALUES(?,?,?,?,?,?,?,?)`, e.SHA, e.MediaType, e.Caption, e.ExternalRef, user, e.OccurredAt, s.nowMS(), e.RunID)
		if err != nil {
			return err
		}
		id, _ = res.LastInsertId()
		if _, err = tx.ExecContext(ctx, `INSERT INTO evidence_links(evidence_id,finding_id,target_id) VALUES(?,?,?)`, id, finding, target); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, s.nowMS(), user, "evidence_added", nil, &id, "evidence attached", "{}")
	})
	return id, err
}
func (s *Store) GetEvidence(ctx context.Context, id int64) (Evidence, error) {
	var e Evidence
	err := s.db.Read.QueryRowContext(ctx, `SELECT id,sha,media_type,caption,external_ref,actor,occurred_at,recorded_at,run_id FROM evidence WHERE id=?`, id).Scan(&e.ID, &e.SHA, &e.MediaType, &e.Caption, &e.ExternalRef, &e.Actor, &e.OccurredAt, &e.RecordedAt, &e.RunID)
	return e, err
}

func (s *Store) importFindingTarget(ctx context.Context, tx *sql.Tx, id int64, user string, host int64, service *int64, evidence string) error {
	ref := TargetRef{"host", host}
	if service != nil {
		ref = TargetRef{"service", *service}
	}
	tid, err := targetTx(ctx, tx, ref)
	if err != nil {
		return err
	}
	var exists int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM finding_assets WHERE finding_id=? AND target_id=?", id, tid).Scan(&exists); err != nil {
		return err
	}
	if err = s.linkFindingTarget(ctx, tx, id, tid, evidence, true); err != nil {
		return err
	}
	if exists > 0 {
		return nil
	}
	return s.findingHistory(ctx, tx, id, user, "expanded", map[string]any{"target": ref}, nil)
}
