package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"corkboard/internal/model"
)

var (
	ErrUnknownTask  = errors.New("unknown task")
	ErrTaskClosed   = errors.New("task is closed; closed tasks are final")
	ErrInvalidInput = errors.New("invalid input")
)

var validTaskState = map[string]bool{
	"open": true, "claimed": true, "blocked": true, "done": true, "wontdo": true,
}

func TaskStateValid(s string) bool { return validTaskState[s] }

type NewTask struct {
	DedupeKey string
	RuleID    string
	HostID    *int64
	ServiceID *int64
	Title     string
	Body      string
	Commands  []string
	Priority  int
}

type TaskFilter struct {
	State    string
	Owner    string
	Priority int
	HostID   *int64

	HideLocked bool
}

func ManualTaskKey(hostID int64, serviceID *int64, title string) string {
	if serviceID != nil {
		return fmt.Sprintf("manual:%d:svc%d:%s", hostID, *serviceID, title)
	}
	return fmt.Sprintf("manual:%d:%s", hostID, title)
}

func (s *Store) CreateTask(ctx context.Context, user string, t NewTask) (int64, bool, error) {
	if t.Title == "" {
		return 0, false, fmt.Errorf("task title is required")
	}
	if t.DedupeKey == "" {
		return 0, false, fmt.Errorf("task dedupe key is required")
	}
	if t.Priority <= 0 {
		t.Priority = 3
	}
	cmds, err := json.Marshal(t.Commands)
	if err != nil {
		return 0, false, err
	}
	now := s.nowMS()
	created := false
	err = s.db.WithTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO tasks (dedupe_key, rule_id, host_id, service_id, title, body, commands,
			 priority, state, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
			 ON CONFLICT(dedupe_key) DO NOTHING`,
			t.DedupeKey, nullable(t.RuleID), t.HostID, t.ServiceID, t.Title, t.Body,
			string(cmds), t.Priority, now, now)
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		created = affected > 0
		if !created {
			return nil
		}
		var id int64
		if err := tx.QueryRowContext(ctx,
			`SELECT id FROM tasks WHERE dedupe_key = ?`, t.DedupeKey).Scan(&id); err != nil {
			return err
		}
		rule := "manual"
		if t.RuleID != "" {
			rule = t.RuleID
		}
		return s.appendEvent(ctx, tx, now, user, EventTaskState, nullablePtr(t.HostID), &id,
			fmt.Sprintf("%s: %s (task %d)", rule, t.Title, id), "{}")
	})
	if err != nil {
		return 0, false, err
	}
	var id int64
	if err := s.db.Read.QueryRowContext(ctx, `SELECT id FROM tasks WHERE dedupe_key = ?`, t.DedupeKey).Scan(&id); err != nil {
		return 0, false, err
	}
	return id, created, nil
}

func (s *Store) ListTasks(ctx context.Context, f TaskFilter) ([]model.Task, error) {
	var conds []string
	var args []any
	if f.State != "" {
		conds = append(conds, "t.state = ?")
		args = append(args, f.State)
	}
	if f.Owner != "" {
		conds = append(conds, "t.owner = ?")
		args = append(args, f.Owner)
	}
	if f.Priority > 0 {
		conds = append(conds, "t.priority = ?")
		args = append(args, f.Priority)
	}
	if f.HostID != nil {
		conds = append(conds, "t.host_id = ?")
		args = append(args, *f.HostID)
	}
	if f.HideLocked {
		conds = append(conds, "(h.status IS NULL OR h.status <> 'locked')")
	}
	q := `SELECT t.id, t.dedupe_key, t.rule_id, t.host_id, t.service_id, h.ip,
		 t.title, t.body, t.commands, t.priority, t.state, t.owner, t.claimed_at,
		 t.created_at, t.updated_at, t.closed_note,
		 IFNULL(sv.port || '/' || sv.proto, '')
		 FROM tasks t LEFT JOIN hosts h ON h.id = t.host_id LEFT JOIN services sv ON sv.id = t.service_id`
	if len(conds) > 0 {
		for i, c := range conds {
			if i == 0 {
				q += " WHERE "
			} else {
				q += " AND "
			}
			q += c
		}
	}
	q += ` ORDER BY t.priority, t.created_at, t.id`
	rows, err := s.db.Read.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetTask(ctx context.Context, id int64) (*model.Task, error) {
	row := s.db.Read.QueryRowContext(ctx,
		`SELECT t.id, t.dedupe_key, t.rule_id, t.host_id, t.service_id, h.ip,
		 t.title, t.body, t.commands, t.priority, t.state, t.owner, t.claimed_at,
		 t.created_at, t.updated_at, t.closed_note,
		 IFNULL(sv.port || '/' || sv.proto, '')
		 FROM tasks t LEFT JOIN hosts h ON h.id = t.host_id LEFT JOIN services sv ON sv.id = t.service_id WHERE t.id = ?`, id)
	t, err := scanTask(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUnknownTask
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

type taskScanner interface {
	Scan(dest ...any) error
}

func scanTask(row taskScanner) (model.Task, error) {
	var (
		t        model.Task
		ruleID   sql.NullString
		hostID   sql.NullInt64
		svcID    sql.NullInt64
		hostIP   sql.NullString
		owner    sql.NullString
		claimed  sql.NullInt64
		commands string
		note     sql.NullString
	)
	err := row.Scan(&t.ID, &t.DedupeKey, &ruleID, &hostID, &svcID, &hostIP,
		&t.Title, &t.Body, &commands, &t.Priority, &t.State, &owner, &claimed,
		&t.CreatedAt, &t.UpdatedAt, &note, &t.Service)
	if err != nil {
		return t, err
	}
	if err := json.Unmarshal([]byte(commands), &t.Commands); err != nil {
		t.Commands = nil
	}
	t.RuleID, t.HostIP = ruleID.String, hostIP.String
	if hostID.Valid {
		t.HostID = &hostID.Int64
	}
	if svcID.Valid {
		t.ServiceID = &svcID.Int64
	}
	t.Owner, t.ClaimedAt, t.ClosedNote = owner.String, claimed.Int64, note.String
	return t, nil
}

func (s *Store) ClaimTask(ctx context.Context, id int64, user string, steal bool) error {
	now := s.nowMS()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var owner sql.NullString
		var state string
		var hostID sql.NullInt64
		err := tx.QueryRowContext(ctx,
			`SELECT owner, state, host_id FROM tasks WHERE id = ?`, id).
			Scan(&owner, &state, &hostID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownTask
		}
		if err != nil {
			return err
		}
		if state == "done" || state == "wontdo" {
			return ErrTaskClosed
		}
		if hostID.Valid {
			var status string
			if err := tx.QueryRowContext(ctx, `SELECT status FROM hosts WHERE id = ?`, hostID.Int64).Scan(&status); err != nil {
				return err
			}
			if status == "locked" {
				return ErrHostLocked
			}
		}
		ownerS := owner.String
		kind := EventClaim
		if ownerS != "" && ownerS != user {
			if !steal {
				return fmt.Errorf("%w: %s", ErrAlreadyClaimed, ownerS)
			}
			kind = EventSteal
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE tasks SET state = 'claimed', owner = ?, claimed_at = ?, updated_at = ? WHERE id = ?`,
			user, now, now, id); err != nil {
			return err
		}
		if hostID.Valid {

			var hostOwner sql.NullString
			var hostStatus string
			err := tx.QueryRowContext(ctx,
				`SELECT owner, status FROM hosts WHERE id = ?`, hostID.Int64).Scan(&hostOwner, &hostStatus)
			if err == nil && hostOwner.String == "" {
				newStatus := hostStatus
				if newStatus == "untouched" {
					newStatus = "in_progress"
				}
				if _, err := tx.ExecContext(ctx,
					`UPDATE hosts SET owner = ?, claimed_at = ?, status = ?, updated_at = ? WHERE id = ?`,
					user, now, newStatus, now, hostID.Int64); err != nil {
					return err
				}
			} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		return s.appendEvent(ctx, tx, now, user, kind, nullablePtr64(&hostID), &id,
			fmt.Sprintf("%s claimed task %d", user, id), "{}")
	})
}

func (s *Store) ReleaseTask(ctx context.Context, id int64, user string) error {
	now := s.nowMS()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var owner sql.NullString
		var state string
		var hostID sql.NullInt64
		err := tx.QueryRowContext(ctx,
			`SELECT owner, state, host_id FROM tasks WHERE id = ?`, id).
			Scan(&owner, &state, &hostID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownTask
		}
		if err != nil {
			return err
		}
		if state == "done" || state == "wontdo" {
			return ErrTaskClosed
		}
		if owner.String != user {
			return ErrNotOwner
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE tasks SET state = 'open', owner = NULL, claimed_at = NULL, updated_at = ? WHERE id = ?`,
			now, id); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, now, user, EventRelease, nullablePtr64(&hostID), &id,
			fmt.Sprintf("%s released task %d", user, id), "{}")
	})
}

func (s *Store) SetTaskState(ctx context.Context, id int64, user, state, note string) error {
	switch state {
	case "done", "blocked":
	default:
		return fmt.Errorf("%w: invalid task state %q (use done or blocked)", ErrInvalidInput, state)
	}
	if state == "blocked" && note == "" {
		return fmt.Errorf("%w: blocking a task requires a reason", ErrInvalidInput)
	}
	now := s.nowMS()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var cur string
		var hostID sql.NullInt64
		err := tx.QueryRowContext(ctx,
			`SELECT state, host_id FROM tasks WHERE id = ?`, id).Scan(&cur, &hostID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownTask
		}
		if err != nil {
			return err
		}
		if cur == "done" || cur == "wontdo" {
			return ErrTaskClosed
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE tasks SET state = ?, closed_note = ?, owner = ?, updated_at = ? WHERE id = ?`,
			state, note, user, now, id); err != nil {
			return err
		}
		summary := fmt.Sprintf("%s set task %d to %s", user, id, state)
		if note != "" {
			summary += " (" + note + ")"
		}
		return s.appendEvent(ctx, tx, now, user, EventTaskState, nullablePtr64(&hostID), &id,
			summary, jsonOr(map[string]string{"note": note}))
	})
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullablePtr(p *int64) *int64 { return p }

func nullablePtr64(n *sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	return &n.Int64
}
