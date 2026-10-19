package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Vantage struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	HostID    *int64 `json:"host_id,omitempty"`
	HostIP    string `json:"host_ip,omitempty"`
	Note      string `json:"note,omitempty"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
}

type Tunnel struct {
	ID          int64  `json:"id"`
	Owner       string `json:"owner"`
	ViaHostID   int64  `json:"via_host_id"`
	ViaHostIP   string `json:"via_host_ip,omitempty"`
	Listener    string `json:"listener"`
	Destination string `json:"destination"`
	Vantage     string `json:"vantage"`
	State       string `json:"state"`
	StartedAt   *int64 `json:"started_at,omitempty"`
	EndedAt     *int64 `json:"ended_at,omitempty"`
	EndReason   string `json:"end_reason,omitempty"`
	Note        string `json:"note,omitempty"`
	RecordedAt  int64  `json:"recorded_at"`
}

type AccessEdge struct {
	ID               int64  `json:"id,omitempty"`
	Key              string `json:"key"`
	Kind             string `json:"kind"`
	Src              string `json:"src,omitempty"`
	Dst              string `json:"dst"`
	SrcLabel         string `json:"src_label"`
	DstLabel         string `json:"dst_label"`
	Level            string `json:"level,omitempty"`
	ViaEdgeID        *int64 `json:"via_edge_id,omitempty"`
	CredID           *int64 `json:"cred_id,omitempty"`
	FindingID        *int64 `json:"finding_id,omitempty"`
	EvidenceID       *int64 `json:"evidence_id,omitempty"`
	CompromiseID     *int64 `json:"compromise_id,omitempty"`
	Note             string `json:"note,omitempty"`
	Actor            string `json:"actor"`
	Source           string `json:"source"`
	OccurredAt       *int64 `json:"occurred_at,omitempty"`
	RecordedAt       int64  `json:"recorded_at"`
	EndedAt          *int64 `json:"ended_at,omitempty"`
	EndedRecordedAt  *int64 `json:"ended_recorded_at,omitempty"`
	EndReason        string `json:"end_reason,omitempty"`
	EndedBy          string `json:"ended_by,omitempty"`
	Corrects         *int64 `json:"corrects,omitempty"`
	CorrectionReason string `json:"correction_reason,omitempty"`
	SupersededBy     *int64 `json:"superseded_by,omitempty"`
	supersededAt     int64
	Derived          bool   `json:"derived"`
	State            string `json:"state"`
	srcHost, dstHost int64
}

type EdgeInput struct {
	Kind             string `json:"kind"`
	Src              string `json:"src"`
	Dst              string `json:"dst"`
	Level            string `json:"level"`
	ViaEdgeID        *int64 `json:"via_edge_id"`
	CredID           *int64 `json:"cred_id"`
	FindingID        *int64 `json:"finding_id"`
	EvidenceID       *int64 `json:"evidence_id"`
	Note             string `json:"note"`
	OccurredAt       *int64 `json:"occurred_at"`
	Corrects         *int64 `json:"corrects"`
	CorrectionReason string `json:"correction_reason"`
}

var vantageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func (s *Store) AddVantage(ctx context.Context, user string, v Vantage) error {
	if !vantageName.MatchString(v.Name) {
		return fmt.Errorf("vantage name: letters, digits, '.', '_' or '-', up to 64")
	}
	switch v.Kind {
	case "operator", "foothold", "network":
	default:
		return fmt.Errorf("vantage kind must be operator, foothold, or network")
	}
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		if v.HostIP != "" {
			if err := tx.QueryRowContext(ctx, "SELECT id FROM hosts WHERE ip=?", v.HostIP).Scan(&v.HostID); err != nil {
				return ErrUnknownHost
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO vantages(name,kind,host_id,note,created_by,created_at) VALUES(?,?,?,?,?,?)`, v.Name, v.Kind, v.HostID, v.Note, user, s.nowMS()); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("vantage %s already exists", v.Name)
			}
			return err
		}
		return s.appendEvent(ctx, tx, s.nowMS(), user, "vantage_new", v.HostID, nil, "vantage "+v.Name+" ("+v.Kind+")", "{}")
	})
}

func (s *Store) Vantages(ctx context.Context) ([]Vantage, error) {
	rows, err := s.db.Read.QueryContext(ctx, `SELECT v.name,v.kind,v.host_id,COALESCE(h.ip,''),v.note,v.created_by,v.created_at FROM vantages v LEFT JOIN hosts h ON h.id=v.host_id ORDER BY v.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Vantage{}
	for rows.Next() {
		var v Vantage
		if err := rows.Scan(&v.Name, &v.Kind, &v.HostID, &v.HostIP, &v.Note, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) AddTunnel(ctx context.Context, user string, t Tunnel) (int64, error) {
	if len(t.Listener) > 256 || len(t.Destination) > 256 || len(t.Note) > 2048 {
		return 0, fmt.Errorf("tunnel field too long")
	}
	var id int64
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		if t.ViaHostIP != "" {
			if err := tx.QueryRowContext(ctx, "SELECT id FROM hosts WHERE ip=?", t.ViaHostIP).Scan(&t.ViaHostID); err != nil {
				return ErrUnknownHost
			}
		}
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM vantages WHERE name=?", t.Vantage).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("unknown vantage %q; add it first", t.Vantage)
		}
		started := t.StartedAt
		if started == nil {
			now := s.nowMS()
			started = &now
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO tunnels(owner,via_host_id,listener,destination,vantage,started_at,note,recorded_at) VALUES(?,?,?,?,?,?,?,?)`, user, t.ViaHostID, t.Listener, t.Destination, t.Vantage, started, t.Note, s.nowMS())
		if err != nil {
			return err
		}
		id, _ = res.LastInsertId()
		return s.appendEvent(ctx, tx, s.nowMS(), user, "tunnel_new", &t.ViaHostID, &id, fmt.Sprintf("tunnel %d via host to %s (%s)", id, t.Destination, t.Vantage), "{}")
	})
	return id, err
}

func (s *Store) EndTunnel(ctx context.Context, user string, id int64, reason string, at *int64) error {
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("end reason required")
	}
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		if at == nil {
			now := s.nowMS()
			at = &now
		}
		res, err := tx.ExecContext(ctx, `UPDATE tunnels SET state='ended',ended_at=?,end_reason=? WHERE id=? AND state<>'ended'`, *at, reason, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("tunnel %d not found or already ended", id)
		}
		var hid int64
		if err = tx.QueryRowContext(ctx, "SELECT via_host_id FROM tunnels WHERE id=?", id).Scan(&hid); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, s.nowMS(), user, "tunnel_ended", &hid, &id, fmt.Sprintf("tunnel %d ended: %s", id, reason), jsonOr(map[string]any{"occurred_at": *at}))
	})
}

func (s *Store) Tunnels(ctx context.Context) ([]Tunnel, error) {
	rows, err := s.db.Read.QueryContext(ctx, `SELECT t.id,t.owner,t.via_host_id,h.ip,t.listener,t.destination,t.vantage,t.state,t.started_at,t.ended_at,t.end_reason,t.note,t.recorded_at FROM tunnels t JOIN hosts h ON h.id=t.via_host_id ORDER BY t.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Tunnel{}
	for rows.Next() {
		var t Tunnel
		if err := rows.Scan(&t.ID, &t.Owner, &t.ViaHostID, &t.ViaHostIP, &t.Listener, &t.Destination, &t.Vantage, &t.State, &t.StartedAt, &t.EndedAt, &t.EndReason, &t.Note, &t.RecordedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

var edgeLevels = map[string]map[string]bool{
	"auth":  {"valid": true, "admin": true},
	"shell": {"user": true, "admin": true, "system": true, "domain_admin": true},
}

type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func normalizeNode(ctx context.Context, q rowQuerier, key string) (string, error) {
	ip := strings.TrimPrefix(key, "host:")
	if net.ParseIP(ip) == nil {
		return key, nil
	}
	var id int64
	if err := q.QueryRowContext(ctx, "SELECT id FROM hosts WHERE ip=?", ip).Scan(&id); err != nil {
		return "", fmt.Errorf("unknown host %s", ip)
	}
	return "host:" + strconv.FormatInt(id, 10), nil
}

func resolveNode(ctx context.Context, q rowQuerier, key string) (label string, host int64, err error) {
	kind, ref, ok := strings.Cut(key, ":")
	if !ok || ref == "" {
		return "", 0, fmt.Errorf("node %q must be kind:id", key)
	}
	if kind == "vantage" {
		var hid sql.NullInt64
		err = q.QueryRowContext(ctx, "SELECT host_id FROM vantages WHERE name=?", ref).Scan(&hid)
		if errors.Is(err, sql.ErrNoRows) {
			return "", 0, fmt.Errorf("unknown vantage %q", ref)
		}
		return ref, hid.Int64, err
	}
	id, perr := strconv.ParseInt(ref, 10, 64)
	if perr != nil || id <= 0 {
		return "", 0, fmt.Errorf("node %q: invalid ID", key)
	}
	var hid sql.NullInt64
	switch kind {
	case "host":
		err = q.QueryRowContext(ctx, "SELECT ip,id FROM hosts WHERE id=?", id).Scan(&label, &hid)
	case "service":
		err = q.QueryRowContext(ctx, "SELECT h.ip||':'||s.port||'/'||s.proto,h.id FROM services s JOIN hosts h ON h.id=s.host_id WHERE s.id=?", id).Scan(&label, &hid)
	case "application":
		err = q.QueryRowContext(ctx, "SELECT a.origin||CASE WHEN a.realm<>'' THEN ' '||a.realm ELSE '' END,COALESCE(a.host_id,s.host_id) FROM applications a LEFT JOIN services s ON s.id=a.service_id WHERE a.id=?", id).Scan(&label, &hid)
	case "cred":
		err = q.QueryRowContext(ctx, "SELECT CASE WHEN domain<>'' THEN domain||'\\' ELSE '' END||username||' ('||secret_type||')' FROM creds WHERE id=?", id).Scan(&label)
	default:
		return "", 0, fmt.Errorf("node kind must be vantage, host, service, application, or cred")
	}
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, fmt.Errorf("unknown %s", key)
	}
	return label, hid.Int64, err
}

func (s *Store) AddEdge(ctx context.Context, user string, in EdgeInput) (int64, error) {
	switch in.Kind {
	case "reach", "auth", "shell", "cred_found", "cred_used":
	default:
		return 0, fmt.Errorf("kind must be reach, auth, shell, cred_found, or cred_used")
	}
	if levels := edgeLevels[in.Kind]; levels != nil && !levels[in.Level] {
		return 0, fmt.Errorf("%s level must be one of %s", in.Kind, strings.Join(sortedKeys(levels), ", "))
	}
	if edgeLevels[in.Kind] == nil && in.Level != "" {
		return 0, fmt.Errorf("%s edges take no level", in.Kind)
	}
	if in.Kind == "cred_found" && !strings.HasPrefix(in.Dst, "cred:") {
		return 0, fmt.Errorf("cred_found must point at cred:ID")
	}
	if in.Corrects != nil && strings.TrimSpace(in.CorrectionReason) == "" {
		return 0, fmt.Errorf("correction reason required")
	}
	if len(in.Note) > 4096 {
		return 0, fmt.Errorf("note exceeds 4 KiB")
	}
	var id int64
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var err error
		if in.Dst, err = normalizeNode(ctx, tx, in.Dst); err != nil {
			return err
		}
		if in.Src != "" {
			if in.Src, err = normalizeNode(ctx, tx, in.Src); err != nil {
				return err
			}
		}
		dstLabel, dstHost, err := resolveNode(ctx, tx, in.Dst)
		if err != nil {
			return err
		}
		var src any
		if in.Src != "" {
			if _, _, err = resolveNode(ctx, tx, in.Src); err != nil {
				return err
			}
			src = in.Src
		}
		if in.ViaEdgeID != nil {
			var n int
			if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM access_edges WHERE id=?", *in.ViaEdgeID).Scan(&n); err != nil || n == 0 {
				return fmt.Errorf("unknown via edge %d", *in.ViaEdgeID)
			}
		}
		var compromise *int64
		if in.Corrects != nil {
			var corrected sql.NullInt64
			err = tx.QueryRowContext(ctx, "SELECT compromise_id FROM access_edges WHERE id=?", *in.Corrects).Scan(&corrected)
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("unknown edge %d", *in.Corrects)
			}
			if err != nil {
				return err
			}
			if corrected.Valid {
				compromise = &corrected.Int64
			}
		} else if in.Kind == "shell" && strings.HasPrefix(in.Dst, "host:") {
			c, err := s.compromiseTx(ctx, tx, user, dstHost, dstLabel, in.Level, in.FindingID, in.CredID, in.Note)
			if err != nil {
				return err
			}
			compromise = &c
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO access_edges(kind,src,dst,level,via_edge_id,cred_id,finding_id,evidence_id,compromise_id,note,actor,source,occurred_at,recorded_at,corrects,correction_reason)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,'manual',?,?,?,?)`, in.Kind, src, in.Dst, in.Level, in.ViaEdgeID, in.CredID, in.FindingID, in.EvidenceID, compromise, in.Note, user, in.OccurredAt, s.nowMS(), in.Corrects, in.CorrectionReason)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("edge %d is already corrected", *in.Corrects)
			}
			return err
		}
		id, _ = res.LastInsertId()
		var hid *int64
		if dstHost > 0 {
			hid = &dstHost
		}
		summary := fmt.Sprintf("%s %s → %s", in.Kind, orUnknown(in.Src), dstLabel)
		if in.Corrects != nil {
			summary = fmt.Sprintf("corrected edge %d: %s", *in.Corrects, summary)
		}
		return s.appendEvent(ctx, tx, s.nowMS(), user, "access_edge", hid, &id, summary, jsonOr(map[string]any{"occurred_at": in.OccurredAt, "kind": in.Kind}))
	})
	return id, err
}

func (s *Store) EndEdge(ctx context.Context, user string, id int64, reason string, at *int64) error {
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("end reason required")
	}
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		now := s.nowMS()
		if at == nil {
			at = &now
		}
		res, err := tx.ExecContext(ctx, `UPDATE access_edges SET ended_at=?,ended_recorded_at=?,end_reason=?,ended_by=? WHERE id=? AND ended_at IS NULL AND NOT EXISTS(SELECT 1 FROM access_edges c WHERE c.corrects=access_edges.id)`, *at, now, reason, user, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("edge %d not found, already ended, or corrected", id)
		}
		return s.appendEvent(ctx, tx, now, user, "access_ended", nil, &id, fmt.Sprintf("access edge %d ended: %s", id, reason), jsonOr(map[string]any{"occurred_at": *at}))
	})
}

type LedgerFilter struct {
	AsOf    int64
	Known   bool
	Node    string
	CredID  int64
	Kind    string
	Level   string
	Actor   string
	Derived bool
}

func (s *Store) Ledger(ctx context.Context, f LedgerFilter) ([]AccessEdge, error) {
	tx, err := s.db.Read.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if f.Node != "" {
		if f.Node, err = normalizeNode(ctx, tx, f.Node); err != nil {
			return nil, err
		}
	}
	edges, err := storedEdges(ctx, tx)
	if err != nil {
		return nil, err
	}
	if f.Derived {
		for _, load := range []func(context.Context, *sql.Tx) ([]AccessEdge, error){derivedReach, derivedAuth, derivedTunnels} {
			more, err := load(ctx, tx)
			if err != nil {
				return nil, err
			}
			edges = append(edges, more...)
		}
	}
	type node struct {
		label string
		host  int64
	}
	cache := map[string]node{}
	resolve := func(key string) node {
		if key == "" {
			return node{label: "unknown source"}
		}
		if n, ok := cache[key]; ok {
			return n
		}
		label, host, err := resolveNode(ctx, tx, key)
		if err != nil {
			label = key
		}
		cache[key] = node{label, host}
		return cache[key]
	}
	var filterHost int64
	if strings.HasPrefix(f.Node, "host:") {
		filterHost, _ = strconv.ParseInt(f.Node[5:], 10, 64)
	}
	out := []AccessEdge{}
	for _, e := range edges {
		src, dst := resolve(e.Src), resolve(e.Dst)
		e.SrcLabel, e.DstLabel, e.srcHost, e.dstHost = src.label, dst.label, src.host, dst.host
		if f.Kind != "" && e.Kind != f.Kind || f.Level != "" && e.Level != f.Level || f.Actor != "" && e.Actor != f.Actor {
			continue
		}
		if f.CredID > 0 && (e.CredID == nil || *e.CredID != f.CredID) && e.Src != "cred:"+strconv.FormatInt(f.CredID, 10) && e.Dst != "cred:"+strconv.FormatInt(f.CredID, 10) {
			continue
		}
		if f.Node != "" && e.Src != f.Node && e.Dst != f.Node && (filterHost == 0 || e.srcHost != filterHost && e.dstHost != filterHost) {
			continue
		}
		e.State = "active"
		if f.AsOf > 0 {
			start, end := e.RecordedAt, e.EndedRecordedAt
			if !f.Known {
				if e.OccurredAt != nil {
					start = *e.OccurredAt
				}
				end = e.EndedAt
			}
			if start > f.AsOf {
				continue
			}

			if e.SupersededBy != nil && (!f.Known || e.supersededAt <= f.AsOf) {
				continue
			}
			if end != nil && *end <= f.AsOf {
				e.State = "ended"
			}
		} else if e.EndedAt != nil {
			e.State = "ended"
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return edgeTime(out[i]) < edgeTime(out[j]) })
	return out, nil
}

func edgeTime(e AccessEdge) int64 {
	if e.OccurredAt != nil {
		return *e.OccurredAt
	}
	return e.RecordedAt
}

func storedEdges(ctx context.Context, tx *sql.Tx) ([]AccessEdge, error) {
	rows, err := tx.QueryContext(ctx, `SELECT e.id,e.kind,COALESCE(e.src,''),e.dst,e.level,e.via_edge_id,e.cred_id,e.finding_id,e.evidence_id,e.compromise_id,e.note,e.actor,e.source,
		e.occurred_at,e.recorded_at,e.ended_at,e.ended_recorded_at,e.end_reason,e.ended_by,e.corrects,e.correction_reason,c.id,COALESCE(c.recorded_at,0)
		FROM access_edges e LEFT JOIN access_edges c ON c.corrects=e.id ORDER BY e.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessEdge
	for rows.Next() {
		var e AccessEdge
		if err := rows.Scan(&e.ID, &e.Kind, &e.Src, &e.Dst, &e.Level, &e.ViaEdgeID, &e.CredID, &e.FindingID, &e.EvidenceID, &e.CompromiseID, &e.Note, &e.Actor, &e.Source,
			&e.OccurredAt, &e.RecordedAt, &e.EndedAt, &e.EndedRecordedAt, &e.EndReason, &e.EndedBy, &e.Corrects, &e.CorrectionReason, &e.SupersededBy, &e.supersededAt); err != nil {
			return nil, err
		}
		e.Key = "edge:" + strconv.FormatInt(e.ID, 10)
		out = append(out, e)
	}
	return out, rows.Err()
}

func derivedReach(ctx context.Context, tx *sql.Tx) ([]AccessEdge, error) {
	rows, err := tx.QueryContext(ctx, `SELECT s.id,v.vantage,v.observed_at,r.uploaded_by FROM service_views v
		JOIN services s ON s.host_id=v.host_id AND s.proto=v.proto AND s.port=v.port JOIN runs r ON r.id=v.run_id
		WHERE v.vantage<>'' AND v.state='open'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessEdge
	for rows.Next() {
		var sid, at int64
		var vantage, actor string
		if err := rows.Scan(&sid, &vantage, &at, &actor); err != nil {
			return nil, err
		}
		occurred := at
		out = append(out, AccessEdge{Key: fmt.Sprintf("reach:%d:%s", sid, vantage), Kind: "reach", Src: "vantage:" + vantage, Dst: "service:" + strconv.FormatInt(sid, 10),
			Actor: actor, Source: "scan", OccurredAt: &occurred, RecordedAt: at, Derived: true})
	}
	return out, rows.Err()
}

func derivedAuth(ctx context.Context, tx *sql.Tx) ([]AccessEdge, error) {
	rows, err := tx.QueryContext(ctx, `SELECT r.id,w.cred_id,w.endpoint_id,t.kind||':'||t.ref_id,r.result,r.occurred_at,r.recorded_at,r.actor,r.source,r.confirmed_loss
		FROM check_results r JOIN check_work w ON w.id=r.work_id JOIN auth_endpoints e ON e.id=w.endpoint_id JOIN target_details t ON t.id=e.target_id
		WHERE r.accepted_current=1 AND (r.result IN ('valid','admin') OR r.confirmed_loss=1) ORDER BY COALESCE(r.occurred_at,r.recorded_at),r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessEdge
	open := map[string]int{}
	for rows.Next() {
		var id, cred, endpoint, recorded int64
		var dst, result, actor, source string
		var occurred *int64
		var loss bool
		if err := rows.Scan(&id, &cred, &endpoint, &dst, &result, &occurred, &recorded, &actor, &source, &loss); err != nil {
			return nil, err
		}
		k := fmt.Sprintf("%d:%d", cred, endpoint)
		if loss {
			if i, ok := open[k]; ok {
				at := recorded
				if occurred != nil {
					at = *occurred
				}
				out[i].EndedAt, out[i].EndedRecordedAt, out[i].EndReason, out[i].EndedBy = &at, &recorded, "confirmed access loss", actor
				delete(open, k)
			}
			continue
		}
		if _, ok := open[k]; ok {
			continue
		}
		c := cred
		open[k] = len(out)
		out = append(out, AccessEdge{Key: fmt.Sprintf("auth:%d", id), Kind: "auth", Src: "cred:" + strconv.FormatInt(cred, 10), Dst: dst, Level: result, CredID: &c,
			Actor: actor, Source: "check:" + source, OccurredAt: occurred, RecordedAt: recorded, Derived: true})
	}
	return out, rows.Err()
}

func derivedTunnels(ctx context.Context, tx *sql.Tx) ([]AccessEdge, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,owner,via_host_id,vantage,listener,destination,started_at,ended_at,end_reason,note,recorded_at FROM tunnels`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessEdge
	for rows.Next() {
		var id, via, recorded int64
		var owner, vantage, listener, dest, reason, note string
		var started, ended *int64
		if err := rows.Scan(&id, &owner, &via, &vantage, &listener, &dest, &started, &ended, &reason, &note, &recorded); err != nil {
			return nil, err
		}
		e := AccessEdge{Key: fmt.Sprintf("tunnel:%d", id), Kind: "tunnel", Src: "host:" + strconv.FormatInt(via, 10), Dst: "vantage:" + vantage,
			Note: strings.TrimSpace(fmt.Sprintf("tunnel %d %s → %s %s", id, listener, dest, note)), Actor: owner, Source: "tunnel",
			OccurredAt: started, RecordedAt: recorded, EndedAt: ended, EndReason: reason, Derived: true}
		if ended != nil {
			e.EndedRecordedAt = ended
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown source"
	}
	return s
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
