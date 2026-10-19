package server

import (
	"corkboard/internal/store"
	"net/http"
	"strconv"
)

func checkFilter(r *http.Request) (store.CheckFilter, error) {
	q := r.URL.Query()
	cred, _ := strconv.ParseInt(q.Get("cred_id"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	f := store.CheckFilter{CredID: cred, Vantage: "*", State: q.Get("state"), Applicability: q.Get("applicability"), Limit: limit, Offset: offset}
	if q.Has("vantage") {
		f.Vantage = q.Get("vantage")
	}
	if q.Get("target") != "" {
		ref, err := store.ParseTarget(q.Get("target"))
		if err != nil {
			return f, err
		}
		f.Target = &ref
	}
	return f, nil
}
func (s *Server) handleChecks(w http.ResponseWriter, r *http.Request) {
	f, err := checkFilter(r)
	if err != nil {
		writeErr(w, 400, "invalid_filter", err.Error())
		return
	}
	page, err := s.store.Checks(r.Context(), f)
	if err != nil {
		writeErr(w, 400, "invalid_filter", err.Error())
		return
	}
	writeJSON(w, 200, page)
}
func (s *Server) handleCheckAction(w http.ResponseWriter, r *http.Request) {
	var in store.CheckAction
	if err := decodeJSON(r, &in); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if err := s.store.CheckAction(r.Context(), userFrom(r.Context()), in); err != nil {
		writeErr(w, 409, "check_conflict", err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) handleCheckResult(w http.ResponseWriter, r *http.Request) {
	var in store.CheckResultInput
	if err := decodeJSON(r, &in); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	id, err := s.store.RecordCheck(r.Context(), userFrom(r.Context()), in)
	if err != nil {
		writeErr(w, 400, "invalid_result", err.Error())
		return
	}
	writeJSON(w, 201, map[string]int64{"id": id})
}
func (s *Server) handleCheckHistory(w http.ResponseWriter, r *http.Request) {
	cred, _ := strconv.ParseInt(r.URL.Query().Get("cred_id"), 10, 64)
	endpoint, _ := strconv.ParseInt(r.URL.Query().Get("endpoint_id"), 10, 64)
	history, err := s.store.CheckHistory(r.Context(), cred, endpoint)
	if err != nil {
		writeErr(w, 500, "internal_error", "could not read check history")
		return
	}
	writeJSON(w, 200, history)
}
func (s *Server) handleCredentialProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		p, err := s.store.CredentialProfiles(r.Context())
		if err != nil {
			writeErr(w, 500, "internal_error", "could not read credential profiles")
			return
		}
		writeJSON(w, 200, p)
		return
	}
	var p store.CredentialProfile
	if err := decodeJSON(r, &p); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if err := s.store.SetCredentialProfile(r.Context(), userFrom(r.Context()), p); err != nil {
		writeErr(w, 400, "invalid_profile", err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) handleApplicability(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CredID     int64  `json:"cred_id"`
		EndpointID int64  `json:"endpoint_id"`
		Decision   string `json:"decision"`
		Reason     string `json:"reason"`
	}
	if err := decodeJSON(r, &in); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if err := s.store.SetCheckApplicability(r.Context(), userFrom(r.Context()), in.CredID, in.EndpointID, in.Decision, in.Reason); err != nil {
		writeErr(w, 400, "invalid_applicability", err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) handleAccessObservations(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		cred, _ := strconv.ParseInt(r.URL.Query().Get("cred_id"), 10, 64)
		rows, err := s.store.AccessObservations(r.Context(), cred)
		if err != nil {
			writeErr(w, 500, "internal_error", "could not read access history")
			return
		}
		writeJSON(w, 200, rows)
		return
	}
	var in struct {
		ID       int64  `json:"id"`
		Endpoint int64  `json:"endpoint_id"`
		Reason   string `json:"reason"`
	}
	if err := decodeJSON(r, &in); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if err := s.store.AssociateObservation(r.Context(), userFrom(r.Context()), in.ID, in.Endpoint, in.Reason); err != nil {
		writeErr(w, 400, "invalid_association", err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) handlePatchApplication(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var in store.ApplicationPatch
	if err := decodeJSON(r, &in); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if err := s.store.PatchApplication(r.Context(), userFrom(r.Context()), id, in); err != nil {
		writeErr(w, 400, "invalid_application", err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
