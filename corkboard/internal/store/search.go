package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type SearchOptions struct {
	Query  string
	Kind   string
	Limit  int
	Cursor string
}
type SearchHit struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Title   string `json:"title"`
	Excerpt string `json:"excerpt"`
	Asset   string `json:"asset"`
	Link    string `json:"link"`
	Reason  string `json:"reason"`
	Rank    int    `json:"-"`
}
type SearchPage struct {
	Results    []SearchHit `json:"results"`
	NextCursor string      `json:"next_cursor,omitempty"`
}
type searchCursor struct {
	Rank int    `json:"rank"`
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

var searchKinds = map[string]bool{"host": true, "service": true, "script": true, "note": true, "task": true, "finding": true, "evidence": true, "application": true, "credential": true}

func (s *Store) Search(ctx context.Context, o SearchOptions) (SearchPage, error) {
	result := SearchPage{Results: []SearchHit{}}
	q := strings.TrimSpace(o.Query)
	if q == "" || len(q) > 512 {
		return result, fmt.Errorf("query must contain 1–512 bytes")
	}
	if o.Kind != "" && !searchKinds[o.Kind] {
		return result, fmt.Errorf("invalid search kind")
	}
	if o.Limit <= 0 {
		o.Limit = 50
	}
	if o.Limit > 100 {
		o.Limit = 100
	}
	escaped := strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(q)
	query := `WITH matches AS (SELECT kind,id,title,asset,link,CASE WHEN title=? COLLATE NOCASE OR id=? OR (kind='host' AND EXISTS(SELECT 1 FROM hostnames hn WHERE hn.host_id=CAST(d.id AS INTEGER) AND hn.name=? COLLATE NOCASE)) THEN 0 WHEN (kind='host' AND EXISTS(SELECT 1 FROM hostnames hn WHERE hn.host_id=CAST(d.id AS INTEGER) AND hn.name LIKE ? ESCAPE '\')) OR title LIKE ? ESCAPE '\' THEN 1 ELSE 2 END rank,CASE WHEN instr(lower(title),lower(?))>0 THEN substr(title,1,200) ELSE substr(body,MAX(1,instr(lower(body),lower(?))-60),200) END excerpt FROM search_documents d WHERE (title LIKE ? ESCAPE '\' OR body LIKE ? ESCAPE '\' OR id=?)`
	args := []any{q, q, q, escaped + "%", escaped + "%", q, q, "%" + escaped + "%", "%" + escaped + "%", q}
	if o.Kind != "" {
		query += " AND kind=?"
		args = append(args, o.Kind)
	}
	query += ") SELECT kind,id,title,asset,link,rank,excerpt FROM matches"
	if o.Cursor != "" {
		if len(o.Cursor) > 1024 {
			return result, fmt.Errorf("invalid search cursor")
		}
		b, err := base64.RawURLEncoding.DecodeString(o.Cursor)
		if err != nil {
			return result, fmt.Errorf("invalid search cursor")
		}
		var c searchCursor
		if err = json.Unmarshal(b, &c); err != nil || c.Rank < 0 || c.Rank > 2 || !searchKinds[c.Kind] {
			return result, fmt.Errorf("invalid search cursor")
		}
		query += " WHERE (rank,kind,id)>(?,?,?)"
		args = append(args, c.Rank, c.Kind, c.ID)
	}
	query += " ORDER BY rank,kind,id LIMIT ?"
	args = append(args, o.Limit+1)
	rows, err := s.db.Read.QueryContext(ctx, query, args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var h SearchHit
		if err = rows.Scan(&h.Kind, &h.ID, &h.Title, &h.Asset, &h.Link, &h.Rank, &h.Excerpt); err != nil {
			return result, err
		}
		h.Reason = []string{"exact name/address or ID", "name/title prefix", "text match"}[h.Rank]
		result.Results = append(result.Results, h)
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if len(result.Results) > o.Limit {
		last := result.Results[o.Limit-1]
		b, _ := json.Marshal(searchCursor{last.Rank, last.Kind, last.ID})
		result.NextCursor = base64.RawURLEncoding.EncodeToString(b)
		result.Results = result.Results[:o.Limit]
	}
	return result, nil
}
