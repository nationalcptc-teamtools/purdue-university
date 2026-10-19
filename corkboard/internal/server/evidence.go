package server

import (
	"corkboard/internal/store"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

func (s *Server) handleEvidenceUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeErr(w, 400, "invalid_evidence", "invalid multipart evidence")
		return
	}
	defer r.MultipartForm.RemoveAll()
	finding, _ := strconv.ParseInt(r.FormValue("finding_id"), 10, 64)
	var target store.TargetRef
	var err error
	if r.FormValue("target") != "" {
		target, err = store.ParseTarget(r.FormValue("target"))
		if err != nil {
			writeErr(w, 400, "invalid_target", err.Error())
			return
		}
	}
	e := store.Evidence{Caption: r.FormValue("caption"), ExternalRef: r.FormValue("external_ref")}
	if e.ExternalRef != "" {
		e.MediaType = "external"
	} else {
		file, _, err := r.FormFile("file")
		if err != nil {
			writeErr(w, 400, "invalid_evidence", "file or external reference required")
			return
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, (5<<20)+1))
		if err != nil || len(data) > 5<<20 {
			writeErr(w, 400, "invalid_evidence", "evidence exceeds 5 MiB")
			return
		}
		media := http.DetectContentType(data)
		if media == "image/png" || media == "image/jpeg" {
			shots, err := s.shotStore()
			if err != nil {
				writeErr(w, 500, "evidence_failed", "evidence storage unavailable")
				return
			}
			e.SHA, _, err = shots.Put(data)
			if err != nil {
				writeErr(w, 400, "invalid_evidence", err.Error())
				return
			}
			e.MediaType = media
		} else {
			if len(data) > 65536 || !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
				writeErr(w, 400, "invalid_evidence", "text evidence must be UTF-8, max 64 KiB")
				return
			}

			if !strings.HasPrefix(media, "text/plain") {
				writeErr(w, 400, "invalid_evidence", "only PNG, JPEG and plain text are accepted")
				return
			}
			sum := sha256.Sum256(data)
			e.SHA = hex.EncodeToString(sum[:])
			e.MediaType = "text/plain"
			dir := filepath.Join(s.dataDir, "evidence")
			if err = os.MkdirAll(dir, 0700); err != nil {
				writeErr(w, 500, "evidence_failed", "evidence storage unavailable")
				return
			}
			path := filepath.Join(dir, e.SHA+".txt")
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err == nil {
				_, err = f.Write(data)
				ce := f.Close()
				if err == nil {
					err = ce
				}
			} else if os.IsExist(err) {
				err = nil
			}
			if err != nil {
				writeErr(w, 500, "evidence_failed", "could not save evidence")
				return
			}
		}
	}
	user := userFrom(r.Context())
	if user == "" {
		user = s.Web().User(r)
	}
	id, err := s.store.AddEvidence(r.Context(), user, finding, target, e)
	if err != nil {
		writeErr(w, 400, "invalid_evidence", err.Error())
		return
	}
	writeJSON(w, 201, map[string]int64{"id": id})
}
func (s *Server) handleEvidenceRead(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	e, err := s.store.GetEvidence(r.Context(), id)
	if err != nil {
		writeErr(w, 404, "not_found", "evidence not found")
		return
	}
	if e.MediaType == "external" {
		writeJSON(w, 200, e)
		return
	}
	var path string
	switch e.MediaType {
	case "text/plain":
		path = filepath.Join(s.dataDir, "evidence", e.SHA+".txt")
	case "image/png":
		path = filepath.Join(s.shotsDir(), e.SHA+".png")
	case "image/jpeg":
		path = filepath.Join(s.shotsDir(), e.SHA+".jpg")
	default:
		writeErr(w, 400, "invalid_evidence", "unsupported evidence")
		return
	}
	if len(e.SHA) != 64 || strings.ContainsAny(e.SHA, "/\\.") {
		writeErr(w, 400, "invalid_evidence", "invalid evidence hash")
		return
	}
	w.Header().Set("Content-Type", e.MediaType+"; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="evidence-%d"`, id))
	http.ServeFile(w, r, path)
}
