package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"corkboard/internal/model"
)

type ClaimContext struct {
	Claim     *model.TargetClaim  `json:"claim,omitempty"`
	HostIP    string              `json:"host_ip,omitempty"`
	HostOwner string              `json:"host_owner,omitempty"`
	Others    []model.TargetClaim `json:"others"`
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func narrowTarget(ref TargetRef) error {
	if ref.Kind != "service" {
		return fmt.Errorf("target claims cover services (a web app is claimed by its port); claim hosts and tasks with cork claim IP|TASKID")
	}
	return nil
}

func (s *Store) ClaimTarget(ctx context.Context, user string, ref TargetRef, steal bool) (ClaimContext, error) {
	if err := narrowTarget(ref); err != nil {
		return ClaimContext{}, err
	}
	var tid int64
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var err error
		if tid, err = targetTx(ctx, tx, ref); err != nil {
			return err
		}
		var status string
		err = tx.QueryRowContext(ctx, "SELECT h.status FROM target_details td JOIN hosts h ON h.id=td.host_id WHERE td.id=?", tid).Scan(&status)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if status == "locked" {
			return ErrHostLocked
		}
		var owner string
		err = tx.QueryRowContext(ctx, "SELECT owner FROM target_claims WHERE target_id=?", tid).Scan(&owner)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		kind := EventClaim
		if owner != "" && owner != user {
			if !steal {
				return fmt.Errorf("%w: %s", ErrAlreadyClaimed, owner)
			}
			kind = EventSteal
		}
		now := s.nowMS()
		if _, err = tx.ExecContext(ctx, `INSERT INTO target_claims(target_id,owner,claimed_at) VALUES(?,?,?)
			ON CONFLICT(target_id) DO UPDATE SET owner=excluded.owner,claimed_at=excluded.claimed_at`, tid, user, now); err != nil {
			return err
		}
		var hid *int64
		var label string
		if err = tx.QueryRowContext(ctx, "SELECT host_id,label FROM target_details WHERE id=?", tid).Scan(&hid, &label); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, now, user, kind, hid, &tid, fmt.Sprintf("%s claimed %s", user, label), jsonOr(map[string]any{"target": ref, "from": owner}))
	})
	if err != nil {
		return ClaimContext{}, err
	}
	return s.TargetClaimContext(ctx, ref)
}

func (s *Store) ReleaseTarget(ctx context.Context, user string, ref TargetRef) error {
	if err := narrowTarget(ref); err != nil {
		return err
	}
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		tid, err := targetTx(ctx, tx, ref)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, "DELETE FROM target_claims WHERE target_id=? AND owner=?", tid, user)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotOwner
		}
		var hid *int64
		var label string
		if err = tx.QueryRowContext(ctx, "SELECT host_id,label FROM target_details WHERE id=?", tid).Scan(&hid, &label); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, s.nowMS(), user, EventRelease, hid, &tid, fmt.Sprintf("%s released %s", user, label), jsonOr(map[string]any{"target": ref}))
	})
}

func (s *Store) TargetClaimContext(ctx context.Context, ref TargetRef) (ClaimContext, error) {
	out := ClaimContext{Others: []model.TargetClaim{}}
	if err := narrowTarget(ref); err != nil {
		return out, err
	}
	col := targetColumn(ref.Kind)
	var tid int64
	var hid *int64
	err := s.db.Read.QueryRowContext(ctx, "SELECT d.id,d.host_id FROM work_targets t JOIN target_details d ON d.id=t.id WHERE t."+col+"=?", ref.ID).Scan(&tid, &hid)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if hid == nil {
		claims, err := loadClaims(ctx, s.db.Read, "c.target_id=?", tid)
		if err != nil {
			return out, err
		}
		if len(claims) == 1 {
			out.Claim = &claims[0]
		}
		return out, nil
	}
	if err = s.db.Read.QueryRowContext(ctx, "SELECT ip,COALESCE(owner,'') FROM hosts WHERE id=?", *hid).Scan(&out.HostIP, &out.HostOwner); err != nil {
		return out, err
	}
	claims, err := loadClaims(ctx, s.db.Read, "d.host_id=?", *hid)
	if err != nil {
		return out, err
	}
	for i := range claims {
		if claims[i].TargetID == tid {
			out.Claim = &claims[i]
		} else {
			out.Others = append(out.Others, claims[i])
		}
	}
	return out, nil
}

func loadClaims(ctx context.Context, q queryer, where string, args ...any) ([]model.TargetClaim, error) {
	rows, err := q.QueryContext(ctx, `SELECT c.target_id,d.kind,d.ref_id,d.label,c.owner,c.claimed_at
		FROM target_claims c JOIN target_details d ON d.id=c.target_id WHERE `+where+` ORDER BY d.label`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.TargetClaim
	for rows.Next() {
		var c model.TargetClaim
		if err := rows.Scan(&c.TargetID, &c.Kind, &c.RefID, &c.Label, &c.Owner, &c.ClaimedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) attachClaims(ctx context.Context, hosts []model.Host) error {
	ids := make([]any, len(hosts))
	byID := make(map[int64]*model.Host, len(hosts))
	for i := range hosts {
		ids[i] = hosts[i].ID
		byID[hosts[i].ID] = &hosts[i]
	}
	rows, err := s.db.Read.QueryContext(ctx, `SELECT d.host_id,c.target_id,d.kind,d.ref_id,d.label,c.owner,c.claimed_at
		FROM target_claims c JOIN target_details d ON d.id=c.target_id WHERE d.host_id IN (`+placeholders(len(ids))+`) ORDER BY d.label`, ids...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var hid int64
		var c model.TargetClaim
		if err := rows.Scan(&hid, &c.TargetID, &c.Kind, &c.RefID, &c.Label, &c.Owner, &c.ClaimedAt); err != nil {
			return err
		}
		if h, ok := byID[hid]; ok {
			h.Claims = append(h.Claims, c)
		}
	}
	return rows.Err()
}
