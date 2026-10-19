package server

import (
	"net/http"
	"strconv"
	"strings"

	"corkboard/internal/store"
)

func (s *Server) handleListCreds(w http.ResponseWriter, r *http.Request) {
	creds, err := s.store.ListCreds(r.Context())
	if err != nil {
		s.log.Error("list creds", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "listing creds failed")
		return
	}
	writeJSON(w, http.StatusOK, creds)
}

func (s *Server) handleAddCred(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain     string `json:"domain"`
		Username   string `json:"username"`
		Secret     string `json:"secret"`
		SecretType string `json:"secret_type"`
		Notes      string `json:"notes"`
		Access     []struct {
			IP       string `json:"ip"`
			Protocol string `json:"protocol"`
			Level    string `json:"level"`
		} `json:"access"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if body.Username == "" || body.Secret == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "username and secret are required")
		return
	}
	if !store.ValidSecretType(body.SecretType) {
		writeErr(w, http.StatusBadRequest, "invalid_request", "secret_type must be one of: password, ntlm, aes, ssh_key, ticket, hash_uncracked, other")
		return
	}
	in := store.CredInput{
		Domain:     body.Domain,
		Username:   body.Username,
		Secret:     body.Secret,
		SecretType: body.SecretType,
		Notes:      body.Notes,
	}
	for _, a := range body.Access {
		if !store.ValidAccessProtocol(a.Protocol) || !store.ValidAccessLevel(a.Level) {
			writeErr(w, http.StatusBadRequest, "invalid_request", "access needs a known protocol and level invalid|valid|admin")
			return
		}
		in.Access = append(in.Access, store.CredAccessInput{IP: a.IP, Protocol: a.Protocol, Level: a.Level})
	}
	id, err := s.store.AddCred(r.Context(), userFrom(r.Context()), in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"cred_id": id})
}

func (s *Server) handleAddCredAccess(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "cred id must be an integer")
		return
	}
	var body struct {
		IP       string `json:"ip"`
		Protocol string `json:"protocol"`
		Level    string `json:"level"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if !store.ValidAccessProtocol(body.Protocol) || !store.ValidAccessLevel(body.Level) {
		writeErr(w, http.StatusBadRequest, "invalid_request", "protocol must be smb|ldap|mssql|winrm|rdp|ssh|other and level invalid|valid|admin")
		return
	}
	if err := s.store.AddCredAccess(r.Context(), userFrom(r.Context()), id, body.IP, body.Protocol, body.Level); err != nil {
		s.credErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRevealCred(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "cred id must be an integer")
		return
	}
	secret, err := s.store.RevealCred(r.Context(), id, userFrom(r.Context()))
	if err != nil {
		s.credErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cred_id": id, "secret": secret})
}

func (s *Server) handleCredMatrix(w http.ResponseWriter, r *http.Request) {
	m, err := s.store.CredMatrix(r.Context())
	if err != nil {
		s.log.Error("cred matrix", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "matrix failed")
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) credErr(w http.ResponseWriter, err error) {
	switch {
	case err == store.ErrUnknownCred:
		writeErr(w, http.StatusNotFound, "not_found", "unknown credential")
	case strings.HasPrefix(err.Error(), "unknown host "):
		writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		s.log.Error("cred endpoint", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "request failed")
	}
}
