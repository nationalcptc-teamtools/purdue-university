package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"corkboard/internal/scope"
)

func (s *Store) ApplyScopeZones(ctx context.Context, zoneOf func(ip string, hostnames []string) string, actor string, hostIDs []int64) (outOfScope []string, err error) {
	now := s.nowMS()
	err = s.db.WithTx(ctx, func(tx *sql.Tx) error {
		for _, hid := range hostIDs {
			var ip, status, zone string
			var unlockedBy sql.NullString
			err := tx.QueryRowContext(ctx,
				`SELECT h.ip, h.status, h.scope_zone, a.value
				 FROM hosts h LEFT JOIN host_attrs a ON a.host_id = h.id AND a.key = 'unlocked_by'
				 WHERE h.id = ?`, hid).Scan(&ip, &status, &zone, &unlockedBy)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			hostnames := make([]string, 0, 4)
			rows, err := tx.QueryContext(ctx, `SELECT name FROM hostnames WHERE host_id = ?`, hid)
			if err != nil {
				return err
			}
			for rows.Next() {
				var n string
				if err := rows.Scan(&n); err != nil {
					rows.Close()
					return err
				}
				hostnames = append(hostnames, n)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}

			newZone := zoneOf(ip, hostnames)

			if newZone != zone {
				if _, err := tx.ExecContext(ctx,
					`UPDATE hosts SET scope_zone = ?, updated_at = ? WHERE id = ?`, newZone, now, hid); err != nil {
					return err
				}
			}

			if newZone == string(scope.ZoneCaution) && status != "locked" && !unlockedBy.Valid {
				if _, err := tx.ExecContext(ctx,
					`UPDATE hosts SET status = 'locked', updated_at = ? WHERE id = ?`, now, hid); err != nil {
					return err
				}
				if err := s.appendEvent(ctx, tx, now, "system", EventLockChange, &hid, nil,
					fmt.Sprintf("caution zone: %s locked", ip), "{}"); err != nil {
					return err
				}
			}

			if newZone == string(scope.ZoneOut) && zone != string(scope.ZoneOut) {
				outOfScope = append(outOfScope, ip)
				if err := s.appendEvent(ctx, tx, now, "system", EventScopeAlarm, &hid, nil,
					fmt.Sprintf("OUT OF SCOPE: %s (uploader %s)", ip, actor),
					jsonOr(map[string]string{"ip": ip, "uploader": actor})); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return outOfScope, err
}
