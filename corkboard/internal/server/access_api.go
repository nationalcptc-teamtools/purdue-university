package server

import (
	"net/http"
	"strconv"
	"time"

	"corkboard/internal/store"
)

func ledgerFilter(r *http.Request) (store.LedgerFilter, error) {
	q := r.URL.Query()
	f := store.LedgerFilter{Known: q.Get("known") == "1", Node: q.Get("node"), Kind: q.Get("kind"), Level: q.Get("level"), Actor: q.Get("actor"), Derived: q.Get("derived") != "0"}
	if v := q.Get("as_of"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.AsOf = t.UnixMilli()
		} else if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			f.AsOf = n
		} else {
			return f, errBadParam("as_of must be RFC3339 or epoch milliseconds")
		}
	}
	if v := q.Get("cred"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return f, errBadParam("cred must be a credential ID")
		}
		f.CredID = n
	}
	return f, nil
}

type errBadParam string

func (e errBadParam) Error() string { return string(e) }

func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		f, err := ledgerFilter(r)
		if err != nil {
			writeErr(w, 400, "invalid_filter", err.Error())
			return
		}
		edges, err := s.store.Ledger(r.Context(), f)
		if err != nil {
			writeErr(w, 400, "invalid_filter", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"edges": edges})
		return
	}
	var in store.EdgeInput
	if err := decodeJSON(r, &in); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	id, err := s.store.AddEdge(r.Context(), userFrom(r.Context()), in)
	if err != nil {
		writeErr(w, 400, "invalid_edge", err.Error())
		return
	}
	writeJSON(w, 201, map[string]int64{"id": id})
}

type endInput struct {
	Reason     string `json:"reason"`
	OccurredAt *int64 `json:"occurred_at"`
}

func (s *Server) handleAccessEnd(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid_id", "invalid edge ID")
		return
	}
	var in endInput
	if err := decodeJSON(r, &in); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if err := s.store.EndEdge(r.Context(), userFrom(r.Context()), id, in.Reason, in.OccurredAt); err != nil {
		writeErr(w, 400, "invalid_end", err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleVantages(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		v, err := s.store.Vantages(r.Context())
		if err != nil {
			writeErr(w, 500, "internal_error", "could not read vantages")
			return
		}
		writeJSON(w, 200, v)
		return
	}
	var in store.Vantage
	if err := decodeJSON(r, &in); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if err := s.store.AddVantage(r.Context(), userFrom(r.Context()), in); err != nil {
		writeErr(w, 400, "invalid_vantage", err.Error())
		return
	}
	writeJSON(w, 201, map[string]bool{"ok": true})
}

func (s *Server) handleTunnels(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		t, err := s.store.Tunnels(r.Context())
		if err != nil {
			writeErr(w, 500, "internal_error", "could not read tunnels")
			return
		}
		writeJSON(w, 200, t)
		return
	}
	var in store.Tunnel
	if err := decodeJSON(r, &in); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	id, err := s.store.AddTunnel(r.Context(), userFrom(r.Context()), in)
	if err != nil {
		writeErr(w, 400, "invalid_tunnel", err.Error())
		return
	}
	writeJSON(w, 201, map[string]int64{"id": id})
}

func (s *Server) handleTunnelEnd(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid_id", "invalid tunnel ID")
		return
	}
	var in endInput
	if err := decodeJSON(r, &in); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if err := s.store.EndTunnel(r.Context(), userFrom(r.Context()), id, in.Reason, in.OccurredAt); err != nil {
		writeErr(w, 400, "invalid_end", err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
