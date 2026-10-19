package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type DashStats struct {
	HostsTotal       int
	HostsUntouched   int
	HostsInProgress  int
	HostsDone        int
	HostsCompromised int
	Services         int
	Creds            int
	AdminCreds       int
	OpenP1Tasks      int
}

func (s *Store) DashStats(ctx context.Context) (DashStats, error) {
	var st DashStats
	rd := s.db.Read
	if err := rd.QueryRowContext(ctx, `
		SELECT COUNT(*),
			COALESCE(SUM(status = 'untouched'), 0),
			COALESCE(SUM(status = 'in_progress'), 0),
			COALESCE(SUM(status = 'done'), 0),
			COALESCE(SUM(status = 'compromised'), 0)
		 FROM hosts WHERE scope_zone != 'out'`).
		Scan(&st.HostsTotal, &st.HostsUntouched, &st.HostsInProgress, &st.HostsDone, &st.HostsCompromised); err != nil {
		return st, err
	}
	if err := rd.QueryRowContext(ctx, `SELECT COUNT(*) FROM services s JOIN hosts h ON h.id = s.host_id
		WHERE s.state IN ('open', 'open|filtered') AND h.scope_zone != 'out'`).
		Scan(&st.Services); err != nil {
		return st, err
	}
	if err := rd.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT ca.cred_id),
			COUNT(DISTINCT CASE WHEN ca.level = 'admin' THEN ca.cred_id END)
		 FROM cred_access ca JOIN hosts h ON h.id = ca.host_id
		 WHERE ca.level IN ('valid', 'admin') AND h.scope_zone != 'out'`).
		Scan(&st.Creds, &st.AdminCreds); err != nil {
		return st, err
	}
	if err := rd.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM tasks WHERE state = 'open' AND priority <= 1`).
		Scan(&st.OpenP1Tasks); err != nil {
		return st, err
	}
	return st, nil
}

func (s *Store) MaxEventID(ctx context.Context) (int64, error) {
	var id int64
	err := s.db.Read.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM events`).Scan(&id)
	return id, err
}

func (s *Store) SetCompromise(ctx context.Context, ip, user, level string, viaFindingID, viaCredID *int64, viaText string) error {
	switch level {
	case "user", "admin", "system", "domain_admin":
	default:
		return fmt.Errorf("invalid compromise level %q", level)
	}
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var hostID int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip = ?`, ip).Scan(&hostID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownHost
		}
		if err != nil {
			return err
		}
		id, err := s.compromiseTx(ctx, tx, user, hostID, ip, level, viaFindingID, viaCredID, viaText)
		if err != nil {
			return err
		}
		now := s.nowMS()
		_, err = tx.ExecContext(ctx, `INSERT INTO access_edges(kind,dst,level,cred_id,finding_id,compromise_id,note,actor,source,occurred_at,recorded_at)
			VALUES('shell',?,?,?,?,?,?,?,'owned',?,?)`, fmt.Sprintf("host:%d", hostID), level, viaCredID, viaFindingID, id, viaText, user, now, now)
		return err
	})
}

func (s *Store) compromiseTx(ctx context.Context, tx *sql.Tx, user string, hostID int64, ip, level string, viaFindingID, viaCredID *int64, viaText string) (int64, error) {
	now := s.nowMS()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO compromises (host_id, level, via_finding_id, via_cred_id, via_text, by_user, at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		hostID, level, viaFindingID, viaCredID, viaText, user, now)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	if _, err := tx.ExecContext(ctx,
		`UPDATE hosts SET status = 'compromised', updated_at = ? WHERE id = ?`, now, hostID); err != nil {
		return 0, err
	}
	return id, s.appendEvent(ctx, tx, now, user, EventCompromise, &hostID, nil,
		fmt.Sprintf("%s: %s compromised as %s", user, ip, level),
		jsonOr(map[string]string{"level": level}))
}

func (s *Store) RevealCred(ctx context.Context, id int64, user string) (string, error) {
	var secret string
	err := s.db.Read.QueryRowContext(ctx, `SELECT secret FROM creds WHERE id = ?`, id).Scan(&secret)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: %d", ErrUnknownCred, id)
	}
	if err != nil {
		return "", err
	}
	return secret, nil
}

func EventKinds() []string {
	return []string{
		EventIngest, EventHostNew, EventServiceNew, EventCredNew,
		EventClaim, EventRelease, EventSteal, EventLockChange,
		EventNote, EventCompromise, EventTaskState, EventCredReveal,
		EventCredAccessAdmin, EventFindingState, EventScopeAlarm,
		EventBloodHoundTarget, EventBloodHoundSync, EventServiceExplored, EventPriority,
	}
}

func (s *Store) HostIDByIP(ctx context.Context, ip string) (int64, error) {
	var id int64
	err := s.db.Read.QueryRowContext(ctx, `SELECT id FROM hosts WHERE ip = ?`, ip).Scan(&id)
	return id, err
}
