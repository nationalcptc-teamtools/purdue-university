package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"corkboard/internal/archive"
)

func (s *Server) captureArchive(ctx context.Context) (*archive.Snapshot, error) {
	s.snapshotMu.Lock()
	defer s.snapshotMu.Unlock()
	s.configMu.Lock()
	defer s.configMu.Unlock()
	scopeData, err := s.Scope().YAML()
	if err != nil {
		return nil, err
	}
	return archive.Capture(ctx, archive.Source{DB: s.store.DB(), Screenshots: s.shotsDir(), Scope: scopeData, EngagementName: s.cfg.EngagementName, AppVersion: s.version})
}
func (s *Server) handleArchiveExport(w http.ResponseWriter, r *http.Request) {
	s.exportArchive(w, r, userFrom(r.Context()))
}
func (s *Server) browserArchiveExport(w http.ResponseWriter, r *http.Request) {
	s.exportArchive(w, r, s.Web().User(r))
}
func (s *Server) exportArchive(w http.ResponseWriter, r *http.Request, user string) {
	if err := s.store.LogExportReveal(r.Context(), user); err != nil {
		writeErr(w, 500, "archive_failed", "could not audit archive export")
		return
	}
	snapshot, err := s.captureArchive(r.Context())
	if err != nil {
		writeErr(w, 409, "archive_incomplete", err.Error())
		return
	}
	defer snapshot.Close()
	f, err := os.CreateTemp("", "cork-download-*.zip")
	if err != nil {
		writeErr(w, 500, "archive_failed", "could not create archive staging file")
		return
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = snapshot.Pack(r.Context(), f); err != nil {
		s.log.Error("archive export failed", "err", err)
		writeErr(w, 500, "archive_failed", "archive generation failed")
		return
	}
	if err = f.Sync(); err != nil {
		writeErr(w, 500, "archive_failed", "archive staging write failed")
		return
	}
	info, err := f.Stat()
	if err != nil {
		writeErr(w, 500, "archive_failed", "archive staging failed")
		return
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		writeErr(w, 500, "archive_failed", "archive staging failed")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="engagement.cork.zip"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", fmt.Sprint(info.Size()))
	_, err = io.Copy(w, f)
	if err != nil {
		s.log.Warn("archive download interrupted", "user", user)
	}
}
func (s *Server) handleArchiveInspect(w http.ResponseWriter, r *http.Request) { s.inspectArchive(w, r) }
func (s *Server) browserArchiveInspect(w http.ResponseWriter, r *http.Request) {
	s.inspectArchive(w, r)
}
func (s *Server) inspectArchive(w http.ResponseWriter, r *http.Request) {

	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, 400, "invalid_archive", "expected multipart archive upload")
		return
	}
	f, err := os.CreateTemp("", "cork-inspect-upload-*.zip")
	if err != nil {
		writeErr(w, 500, "archive_failed", "could not stage archive upload")
		return
	}
	defer os.Remove(f.Name())
	defer f.Close()
	found := false
	for {
		part, e := mr.NextPart()
		if e == io.EOF {
			break
		}
		if e != nil {
			writeErr(w, 400, "invalid_archive", "incomplete archive upload")
			return
		}
		if part.FormName() != "file" {
			part.Close()
			continue
		}
		if found {
			part.Close()
			writeErr(w, 400, "invalid_archive", "expected one archive")
			return
		}
		found = true
		n, e := io.Copy(f, io.LimitReader(part, archive.MaxBytes+1))
		part.Close()
		if e != nil || n > archive.MaxBytes {
			writeErr(w, 413, "archive_too_large", "archive upload failed or exceeds 32 GiB")
			return
		}
	}
	if !found {
		writeErr(w, 400, "invalid_archive", "missing archive file")
		return
	}
	m, err := archive.Inspect(r.Context(), f.Name())
	if err != nil {
		writeErr(w, 400, "invalid_archive", err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, m)
}
