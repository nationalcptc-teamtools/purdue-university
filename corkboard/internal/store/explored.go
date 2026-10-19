package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrUnknownService = errors.New("unknown service")

func (s *Store) SetServiceExplored(ctx context.Context, user string, serviceID int64, explored bool) error {
	now := s.nowMS()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var hostID int64
		var ip, proto string
		var port int
		err := tx.QueryRowContext(ctx, `SELECT s.host_id, h.ip, s.proto, s.port FROM services s JOIN hosts h ON h.id = s.host_id WHERE s.id = ?`,
			serviceID).Scan(&hostID, &ip, &proto, &port)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownService
		}
		if err != nil {
			return err
		}
		summary := fmt.Sprintf("%s marked %s:%d/%s explored", user, ip, port, proto)
		if explored {
			_, err = tx.ExecContext(ctx, `UPDATE services SET explored_at = ?, explored_by = ? WHERE id = ?`, now, user, serviceID)
		} else {
			summary = fmt.Sprintf("%s reopened %s:%d/%s", user, ip, port, proto)
			_, err = tx.ExecContext(ctx, `UPDATE services SET explored_at = NULL, explored_by = NULL WHERE id = ?`, serviceID)
		}
		if err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, now, user, EventServiceExplored, &hostID, &serviceID, summary, "{}")
	})
}

func (s *Store) SetPriority(ctx context.Context, ip, user string, priority int) error {
	if priority < 1 || priority > 3 {
		return fmt.Errorf("%w: priority must be 1, 2, or 3", ErrInvalidInput)
	}
	now := s.nowMS()
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var hostID int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip = ?`, ip).Scan(&hostID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownHost
		}
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE hosts SET priority = ?, updated_at = ? WHERE id = ?`, priority, now, hostID); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, now, user, EventPriority, &hostID, nil,
			fmt.Sprintf("%s set %s to P%d", user, ip, priority), "{}")
	})
}
