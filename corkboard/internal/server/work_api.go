package server

import (
	"corkboard/internal/store"
	"errors"
	"net/http"
)

func (s *Server) handleTargetClaims(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		ref, err := store.ParseTarget(r.URL.Query().Get("target"))
		if err != nil {
			writeErr(w, 400, "invalid_target", err.Error())
			return
		}
		cc, err := s.store.TargetClaimContext(r.Context(), ref)
		if err != nil {
			writeErr(w, 400, "invalid_target", err.Error())
			return
		}
		writeJSON(w, 200, cc)
		return
	}
	var in struct {
		Target store.TargetRef `json:"target"`
		Action string          `json:"action"`
		Steal  bool            `json:"steal"`
	}
	if err := decodeJSON(r, &in); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	user := userFrom(r.Context())
	var cc store.ClaimContext
	var err error
	switch in.Action {
	case "claim":
		cc, err = s.store.ClaimTarget(r.Context(), user, in.Target, in.Steal)
	case "release":
		if err = s.store.ReleaseTarget(r.Context(), user, in.Target); err == nil {
			cc, err = s.store.TargetClaimContext(r.Context(), in.Target)
		}
	default:
		writeErr(w, 400, "invalid_action", "action must be claim or release")
		return
	}
	switch {
	case err == nil:
		writeJSON(w, 200, cc)
	case errors.Is(err, store.ErrAlreadyClaimed), errors.Is(err, store.ErrNotOwner), errors.Is(err, store.ErrHostLocked):
		s.hostErr(w, err)
	default:
		writeErr(w, 400, "invalid_target", err.Error())
	}
}
