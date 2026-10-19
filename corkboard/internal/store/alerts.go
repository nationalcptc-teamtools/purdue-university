package store

import (
	"context"
	"database/sql"
	"errors"
)

func (s *Store) AlertSeen(ctx context.Context, key string) (bool, error) {
	var at int64
	err := s.db.Read.QueryRowContext(ctx, `SELECT at FROM alerts_sent WHERE key = ?`, key).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) MarkAlertSent(ctx context.Context, key string) error {
	_, err := s.db.Write.ExecContext(ctx,
		`INSERT INTO alerts_sent (key, at) VALUES (?, ?)
		 ON CONFLICT(key) DO NOTHING`, key, s.nowMS())
	return err
}

func (s *Store) LogEvent(ctx context.Context, actor, kind, summary string, hostID, refID *int64) error {
	return s.appendEvent(ctx, s.db.Write, s.nowMS(), actor, kind, hostID, refID, summary, "{}")
}
