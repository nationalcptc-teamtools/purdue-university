package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"corkboard/internal/store"
)

func (s *Server) handlePurge(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if b.Confirm != s.cfg.EngagementName {
		writeErr(w, http.StatusBadRequest, "confirm_mismatch",
			"confirm must equal the engagement name")
		return
	}
	user := userFrom(r.Context())

	s.bh.Stop()
	if err := s.store.LogEvent(r.Context(), user, store.EventPurge,
		user+" purged all data", nil, nil); err != nil {
		s.log.Error("purge event", "err", err)
	}
	dbPath := s.store.DB().Path
	var removed []string
	for _, f := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Remove(f); err == nil {
			removed = append(removed, f)
		} else if !os.IsNotExist(err) {
			writeErr(w, http.StatusInternalServerError, "purge_failed", err.Error())
			return
		}
	}
	for _, dir := range []string{"screenshots", "evidence", store.BackupDirName} {
		p := filepath.Join(s.dataDir, dir)
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			if err := os.RemoveAll(p); err != nil {
				writeErr(w, http.StatusInternalServerError, "purge_failed", err.Error())
				return
			}
			removed = append(removed, dir)
		}
	}
	s.log.Warn("purged all data", "user", user, "removed", len(removed))
	writeJSON(w, http.StatusOK, map[string]any{"purged": true, "removed": removed})
}
