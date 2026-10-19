package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"corkboard/internal/model"
)

var digestGroups = []struct{ key, title string }{
	{"compromise", "Compromises"},
	{"access", "Credentials and access"},
	{"finding", "Findings and evidence"},
	{"inventory", "New and reopened hosts, services, and applications"},
	{"scope", "Scope and locks"},
	{"claims", "Claims and progress"},
	{"import", "Imports"},
	{"other", "Other"},
}

func digestGroup(kind string) string {
	switch kind {
	case EventCompromise:
		return "compromise"
	case EventCredNew, EventCredAccessAdmin, "check_result", "access_association", "credential_scope",
		"access_edge", "access_ended", "tunnel_new", "tunnel_ended", "vantage_new":
		return "access"
	case "evidence_added":
		return "finding"
	case EventHostNew, EventServiceNew, "endpoint_changed", "application_new", "application_changed":
		return "inventory"
	case EventScopeAlarm, EventLockChange:
		return "scope"

	case EventClaim, EventRelease, EventSteal, EventTaskState, EventNote, EventStale,
		EventServiceExplored, EventPriority, "claim_transfer",
		"handoff", "blocker", "work_checkin", "attempt_added":
		return "claims"
	case EventIngest:
		return "import"
	case EventCredReveal, EventExportSecrets, EventRulesReload, EventBloodHoundSync, EventBloodHoundTarget:
		return ""
	}
	if len(kind) > 8 && kind[:8] == "finding_" || kind == EventFindingState {
		return "finding"
	}
	if len(kind) > 6 && kind[:6] == "check_" {
		return "access"
	}
	return "other"
}

type DigestItem struct {
	model.Event
	HostIP     string `json:"host_ip,omitempty"`
	OccurredAt *int64 `json:"occurred_at,omitempty"`
}

type DigestGroup struct {
	Key   string       `json:"key"`
	Title string       `json:"title"`
	Count int          `json:"count"`
	Items []DigestItem `json:"items"`
}

type Digest struct {
	User    string        `json:"user"`
	After   int64         `json:"after"`
	Through int64         `json:"through"`
	Total   int           `json:"total"`
	Groups  []DigestGroup `json:"groups"`
}

type DigestOptions struct {
	User       string
	After      *int64
	SinceMS    int64
	IncludeOwn bool
	PerGroup   int
}

func (s *Store) Digest(ctx context.Context, o DigestOptions) (Digest, error) {
	d := Digest{User: o.User, Groups: []DigestGroup{}}
	if o.PerGroup <= 0 || o.PerGroup > 200 {
		o.PerGroup = 25
	}

	tx, err := s.db.Read.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return d, err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM events").Scan(&d.Through); err != nil {
		return d, err
	}
	switch {
	case o.After != nil:
		d.After = *o.After
	case o.SinceMS > 0:
		err = tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM events WHERE at < ?", o.SinceMS).Scan(&d.After)
	default:
		err = tx.QueryRowContext(ctx, "SELECT event_id FROM digest_marks WHERE actor=?", o.User).Scan(&d.After)
		if errors.Is(err, sql.ErrNoRows) {
			err = nil
		}
	}
	if err != nil {
		return d, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT e.id,e.at,e.actor,e.kind,e.host_id,e.ref_id,e.summary,e.data,COALESCE(h.ip,''),
		CASE WHEN e.kind='ingest' THEN COALESCE(r.finished_at,r.started_at) WHEN json_valid(e.data) THEN json_extract(e.data,'$.occurred_at') END
		FROM events e LEFT JOIN hosts h ON h.id=e.host_id LEFT JOIN runs r ON e.kind='ingest' AND r.id=e.ref_id
		WHERE e.id>? AND e.id<=? AND (? OR e.actor<>?) ORDER BY e.id DESC`, d.After, d.Through, o.IncludeOwn, o.User)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	byKey := map[string]*DigestGroup{}
	for rows.Next() {
		var it DigestItem
		var occurred sql.NullInt64
		if err = rows.Scan(&it.ID, &it.At, &it.Actor, &it.Kind, &it.HostID, &it.RefID, &it.Summary, &it.Data, &it.HostIP, &occurred); err != nil {
			return d, err
		}
		key := digestGroup(it.Kind)
		if key == "" {
			continue
		}
		if occurred.Valid {
			it.OccurredAt = &occurred.Int64
		}
		g := byKey[key]
		if g == nil {
			g = &DigestGroup{Key: key}
			byKey[key] = g
		}
		g.Count++
		d.Total++
		if len(g.Items) < o.PerGroup {
			g.Items = append(g.Items, it)
		}
	}
	if err = rows.Err(); err != nil {
		return d, err
	}
	for _, def := range digestGroups {
		if g := byKey[def.key]; g != nil {
			g.Title = def.title
			d.Groups = append(d.Groups, *g)
		}
	}
	return d, nil
}

func (s *Store) AckDigest(ctx context.Context, user string, through int64) (int64, error) {
	var mark int64
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var max int64
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM events").Scan(&max); err != nil {
			return err
		}
		if through > max {
			through = max
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO digest_marks(actor,event_id,acked_at) VALUES(?,?,?)
			ON CONFLICT(actor) DO UPDATE SET event_id=MAX(event_id,excluded.event_id),acked_at=excluded.acked_at`, user, through, s.nowMS()); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, "SELECT event_id FROM digest_marks WHERE actor=?", user).Scan(&mark)
	})
	return mark, err
}

func ParseSince(v string, now time.Time) (int64, error) {
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return now.Add(-d).UnixMilli(), nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UnixMilli(), nil
	}
	return 0, fmt.Errorf("since must be a duration like 8h or an RFC3339 time")
}
