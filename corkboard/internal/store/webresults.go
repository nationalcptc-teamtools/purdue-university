package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"corkboard/internal/model"
)

type WebFilter struct {
	Q      string
	Tech   string
	Status string
	Limit  int
}

func (s *Store) ListWebResults(ctx context.Context, f WebFilter) ([]model.WebResult, error) {
	var conds []string
	var args []any
	if q := strings.TrimSpace(f.Q); q != "" {
		like := "%" + escapeLike(q) + "%"
		conds = append(conds, `(wr.url LIKE ? ESCAPE '\' COLLATE NOCASE OR IFNULL(wr.title,'') LIKE ? ESCAPE '\' COLLATE NOCASE)`)
		args = append(args, like, like)
	}
	if tech := strings.TrimSpace(f.Tech); tech != "" {
		like := "%" + escapeLike(tech) + "%"
		conds = append(conds, `EXISTS (SELECT 1 FROM json_each(wr.technologies) je WHERE LOWER(je.value) LIKE LOWER(?))`)
		args = append(args, like)
	}
	switch f.Status {
	case "ok":
		conds = append(conds, `wr.failed = 0 AND wr.status_code BETWEEN 200 AND 399`)
	case "fail":
		conds = append(conds, `(wr.failed = 1 OR wr.status_code = 0 OR wr.status_code >= 400)`)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 500
	}
	query := `SELECT wr.id, wr.host_id, wr.service_id, wr.url, IFNULL(wr.final_url,''), IFNULL(wr.status_code,0),
		IFNULL(wr.title,''), wr.technologies, IFNULL(wr.tls_subject,''), IFNULL(wr.screenshot,''), IFNULL(wr.thumb,''),
		wr.failed, IFNULL(wr.failed_reason,''), IFNULL(wr.probed_at,0), IFNULL(h.ip,''), IFNULL(h.owner,'')
	 FROM web_results wr LEFT JOIN hosts h ON h.id = wr.host_id` +
		whereClause(conds) +
		` ORDER BY wr.probed_at DESC, wr.url LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Read.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.WebResult, 0, 64)
	for rows.Next() {
		var w model.WebResult
		var tech []byte
		var hostID, svcID sql.NullInt64
		if err := rows.Scan(&w.ID, &hostID, &svcID, &w.URL, &w.FinalURL, &w.StatusCode,
			&w.Title, &tech, &w.TLSSubject, &w.Screenshot, &w.Thumb,
			&w.Failed, &w.FailedReason, &w.ProbedAt, &w.HostIP, &w.Owner); err != nil {
			return nil, err
		}
		if hostID.Valid && hostID.Int64 != 0 {
			id := hostID.Int64
			w.HostID = &id
		}
		if svcID.Valid {
			id := svcID.Int64
			w.ServiceID = &id
		}
		_ = json.Unmarshal(tech, &w.Technologies)
		out = append(out, w)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
