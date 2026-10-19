package store

import (
	"context"
	"database/sql"
	"fmt"

	"corkboard/internal/model"
)

var validSeverity = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
}

type FindingFilter struct {
	State string
}

var validFindingState = map[string]bool{
	"candidate": true, "confirmed": true, "rejected": true, "reported": true,
}

func FindingStateValid(s string) bool { return validFindingState[s] }

func (s *Store) ListFindings(ctx context.Context, f FindingFilter) ([]model.Finding, error) {
	q := `SELECT id, dedupe_key, title, severity, source, state, gw_library_title,
		 description, created_at, updated_at, (SELECT COUNT(*) FROM finding_assets a WHERE a.finding_id=findings.id AND a.needs_review=1),report_update FROM findings WHERE merged_into IS NULL`
	var args []any
	if f.State != "" {
		q += ` AND state = ?`
		args = append(args, f.State)
	}
	q += ` ORDER BY id`
	rows, err := s.db.Read.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Finding
	ids := make([]int64, 0)
	for rows.Next() {
		var f model.Finding
		var gw sql.NullString
		if err := rows.Scan(&f.ID, &f.DedupeKey, &f.Title, &f.Severity, &f.Source,
			&f.State, &gw, &f.Description, &f.CreatedAt, &f.UpdatedAt, &f.NeedsReview, &f.ReportUpdate); err != nil {
			return nil, err
		}
		f.GWLibraryTitle = gw.String
		out = append(out, f)
		ids = append(ids, f.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) > 0 {
		if err := s.attachFindingHosts(ctx, out, ids); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) attachFindingHosts(ctx context.Context, findings []model.Finding, ids []int64) error {
	q := `SELECT fh.finding_id, fh.host_id, h.ip, fh.service_id, fh.evidence
		 FROM finding_hosts fh JOIN hosts h ON h.id = fh.host_id
		 WHERE fh.finding_id IN (` + placeholders(len(ids)) + `) ORDER BY fh.id`
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := s.db.Read.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	byID := make(map[int64]*model.Finding, len(findings))
	for i := range findings {
		byID[findings[i].ID] = &findings[i]
	}
	for rows.Next() {
		var (
			fid, hid     int64
			ip, evidence string
			svc          sql.NullInt64
		)
		if err := rows.Scan(&fid, &hid, &ip, &svc, &evidence); err != nil {
			return err
		}
		fh := model.FindingHost{HostID: hid, IP: ip, Evidence: evidence}
		if svc.Valid {
			fh.ServiceID = &svc.Int64
		}
		if f, ok := byID[fid]; ok {
			f.Hosts = append(f.Hosts, fh)
		}
	}
	return rows.Err()
}

func (s *Store) SetFindingState(ctx context.Context, id int64, user, state, gwTitle string) error {
	if state != "" && !validFindingState[state] {
		return fmt.Errorf("invalid finding state %q", state)
	}
	if gwTitle == "" && state == "" {
		return fmt.Errorf("nothing to update")
	}
	return s.EditFinding(ctx, user, id, FindingInput{State: state, GWTitle: gwTitle})
}
