package server

import (
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"corkboard/internal/screenshots"
)

var shotsRe = regexp.MustCompile(`^([0-9a-f]{64})\.(jpg|png)$`)

func (s *Server) shotStore() (*screenshots.Store, error) {
	s.shotsMu.Lock()
	defer s.shotsMu.Unlock()
	if s.shots == nil {
		st, err := screenshots.New(s.shotsDir(), s.store.DB().Write)
		if err != nil {
			return nil, err
		}
		s.shots = st
	}
	return s.shots, nil
}

func (s *Server) handleScreenshotUpload(w http.ResponseWriter, r *http.Request) {
	st, err := s.shotStore()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal_error", "screenshot storage unavailable")
		return
	}
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		if isMaxBytes(err) {
			writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large", "file exceeds max_upload_mb")
			return
		}
		writeErr(w, http.StatusBadRequest, "bad_multipart", "expected a multipart form with one image")
		return
	}
	var (
		data []byte
		ref  string
	)

	ref = r.URL.Query().Get("ref")
	for _, files := range r.MultipartForm.File {
		if len(files) == 0 {
			continue
		}
		f := files[0]
		if ref == "" {
			ref = f.Filename
		}
		file, err := f.Open()
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_multipart", "reading the image failed")
			return
		}
		data, err = io.ReadAll(io.LimitReader(file, screenshots.MaxBytes+1))
		file.Close()
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_multipart", "reading the image failed")
			return
		}
		break
	}
	if data == nil {
		writeErr(w, http.StatusBadRequest, "no_file", "no image field in the multipart form")
		return
	}
	sha, existed, err := st.Put(data)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_image", err.Error())
		return
	}
	if ref != "" {
		if err := st.Attach(filepath.Base(strings.ReplaceAll(ref, `\`, "/")), sha); err != nil {
			s.log.Error("screenshot attach", "err", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sha256": sha, "duplicate": existed})
}

func (s *Server) handleShotAuth(w http.ResponseWriter, r *http.Request) {
	if web := s.Web(); web != nil && web.User(r) != "" {
		s.handleShot(w, r)
		return
	}
	s.requireAuth(http.HandlerFunc(s.handleShot)).ServeHTTP(w, r)
}

func (s *Server) handleShot(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/shots/")
	thumbs := strings.HasPrefix(rest, "thumbs/")
	if thumbs {
		rest = strings.TrimPrefix(rest, "thumbs/")
	}
	m := shotsRe.MatchString(rest)
	if !m {
		http.NotFound(w, r)
		return
	}
	sha, ext := shotsRe.FindStringSubmatch(rest)[1], shotsRe.FindStringSubmatch(rest)[2]
	if ext == "png" && thumbs {

		http.NotFound(w, r)
		return
	}
	st, err := s.shotStore()
	if err != nil {
		http.Error(w, "storage unavailable", http.StatusInternalServerError)
		return
	}
	if thumbs {
		f, err := st.OpenThumb(sha)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Cache-Control", "private, max-age=86400")
		_, _ = io.Copy(w, f)
		return
	}
	f, typ, err := st.Open(sha)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", typ)
	w.Header().Set("Cache-Control", "private, max-age=86400")
	_, _ = io.Copy(w, f)
}
