package server

import (
	"net/http"
	"strconv"

	"corkboard/internal/store"
)

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	f := store.FindingFilter{State: r.URL.Query().Get("state")}
	if f.State != "" && !store.FindingStateValid(f.State) {
		writeErr(w, http.StatusBadRequest, "invalid_request", "state must be candidate|confirmed|rejected|reported")
		return
	}
	list, err := s.store.ListFindings(r.Context(), f)
	if err != nil {
		s.log.Error("list findings", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "listing findings failed")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handlePatchFinding(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid_request", "finding id must be a positive integer")
		return
	}
	var body store.FindingInput
	if err := decodeJSON(r, &body); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if err := s.store.EditFinding(r.Context(), userFrom(r.Context()), id, body); err != nil {
		writeErr(w, 400, "invalid_request", err.Error())
		return
	}
	writeJSON(w, 200, map[string]int64{"id": id})
}
func (s *Server) handleCreateFinding(w http.ResponseWriter, r *http.Request) {
	var in store.FindingInput
	if err := decodeJSON(r, &in); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	id, err := s.store.CreateFinding(r.Context(), userFrom(r.Context()), in)
	if err != nil {
		writeErr(w, 400, "invalid_request", err.Error())
		return
	}
	writeJSON(w, 201, map[string]int64{"id": id})
}
func (s *Server) handleFindingDetail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.store.FindingDetail(r.Context(), id)
	if err != nil {
		writeErr(w, 404, "not_found", "finding not found")
		return
	}
	writeJSON(w, 200, d)
}
func (s *Server) handleApplications(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		apps, err := s.store.Applications(r.Context())
		if err != nil {
			writeErr(w, 500, "internal_error", "could not list applications")
			return
		}
		writeJSON(w, 200, apps)
		return
	}
	var a store.Application
	if err := decodeJSON(r, &a); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	id, err := s.store.AddApplication(r.Context(), userFrom(r.Context()), a)
	if err != nil {
		writeErr(w, 400, "invalid_request", err.Error())
		return
	}
	writeJSON(w, 201, map[string]int64{"id": id})
}
