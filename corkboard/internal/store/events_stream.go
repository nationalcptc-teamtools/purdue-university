package store

import (
	"context"
	"corkboard/internal/model"
)

func (s *Store) EventsAfter(ctx context.Context, id int64, limit int) ([]model.Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	rows, err := s.db.Read.QueryContext(ctx, `SELECT id, at, actor, kind, host_id, ref_id, summary, data FROM events WHERE id > ? ORDER BY id LIMIT ?`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.Event
	for rows.Next() {
		var e model.Event
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Kind, &e.HostID, &e.RefID, &e.Summary, &e.Data); err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}
