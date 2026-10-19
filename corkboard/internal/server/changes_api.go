package server

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"corkboard/internal/store"
)

func DigestOptionsFrom(r *http.Request, user string) (store.DigestOptions, error) {
	q := r.URL.Query()
	o := store.DigestOptions{User: user, IncludeOwn: q.Get("all") == "1"}
	if v := q.Get("after"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return o, fmt.Errorf("after must be an event ID")
		}
		o.After = &n
	}
	if v := q.Get("since"); v != "" {
		ms, err := store.ParseSince(v, time.Now())
		if err != nil {
			return o, err
		}
		o.SinceMS = ms
	}
	return o, nil
}

func (s *Server) handleChanges(w http.ResponseWriter, r *http.Request) {
	o, err := DigestOptionsFrom(r, userFrom(r.Context()))
	if err != nil {
		writeErr(w, 400, "invalid_since", err.Error())
		return
	}
	d, err := s.store.Digest(r.Context(), o)
	if err != nil {
		writeErr(w, 500, "internal_error", "could not read changes")
		return
	}
	writeJSON(w, 200, d)
}

func (s *Server) handleChangesAck(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Through int64 `json:"through"`
	}
	if err := decodeJSON(r, &in); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	mark, err := s.store.AckDigest(r.Context(), userFrom(r.Context()), in.Through)
	if err != nil {
		writeErr(w, 500, "internal_error", "could not acknowledge")
		return
	}
	writeJSON(w, 200, map[string]int64{"mark": mark})
}
