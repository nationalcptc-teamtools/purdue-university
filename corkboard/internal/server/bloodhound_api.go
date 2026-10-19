package server

import (
	"corkboard/internal/bloodhound"
	"net/http"
)

func (s *Server) handleBloodHoundStatus(w http.ResponseWriter, r *http.Request) {
	d, err := s.bh.Status(r.Context())
	if err != nil {
		writeErr(w, 500, "internal_error", "could not read BloodHound status")
		return
	}
	writeJSON(w, 200, d)
}

func (s *Server) handleBloodHoundCheck(w http.ResponseWriter, r *http.Request) {
	d, err := s.bh.Check(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, "bloodhound_unavailable", err.Error())
		return
	}
	writeJSON(w, 200, d)
}

func (s *Server) handleBloodHoundTarget(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Kind     string `json:"kind"`
		Identity string `json:"identity"`
		IP       string `json:"ip"`
	}
	if err := decodeJSON(r, &b); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	var hostID *int64
	if b.Kind == "Computer" {
		h, err := s.store.GetHost(r.Context(), b.IP)
		if err != nil {
			writeErr(w, 400, "invalid_request", "Computer requires an existing compromised host IP")
			return
		}
		hostID = &h.Host.ID
	} else if b.IP != "" {
		writeErr(w, 400, "invalid_request", "IP is only used for Computer mappings")
		return
	}
	t, err := s.store.SaveBloodHoundTarget(r.Context(), userFrom(r.Context()), b.Kind, b.Identity, hostID)
	if err != nil {
		writeErr(w, 400, "invalid_request", err.Error())
		return
	}
	if s.cfg.BloodHound.Enabled && s.cfg.BloodHound.AutoSync {
		s.bh.Wake()
	}
	writeJSON(w, 200, t)
}

func (s *Server) handleBloodHoundSync(w http.ResponseWriter, r *http.Request) {
	if err := s.bh.RequestSync(r.Context()); err != nil {
		code := http.StatusBadGateway
		if err == bloodhound.ErrDisabled {
			code = http.StatusConflict
		}
		writeErr(w, code, "bloodhound_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"queued": true})
}
