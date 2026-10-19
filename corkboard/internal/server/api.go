package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"corkboard/internal/ingest"
	"corkboard/internal/ingest/gowitness"
	"corkboard/internal/ingest/nmap"
	"corkboard/internal/ingest/nuclei"
	"corkboard/internal/store"
)

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": s.version})
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"user":       userFrom(r.Context()),
		"version":    s.version,
		"engagement": s.cfg.EngagementName,
	})
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since := int64(0)
	if v := q.Get("since"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "invalid_request", "since must be a non-negative integer")
			return
		}
		since = n
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeErr(w, http.StatusBadRequest, "invalid_request", "limit must be an integer in 1-500")
			return
		}
		limit = n
	}
	var kinds []string
	if v := q.Get("kind"); v != "" {
		kinds = strings.Split(v, ",")
	}
	events, err := s.store.ListEvents(r.Context(), since, limit, kinds, nil)
	if err != nil {
		s.log.Error("list events", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "listing events failed")
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleIngestBatch(w http.ResponseWriter, r *http.Request) {
	var b ingest.Batch
	if err := decodeJSON(r, &b); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if b.Run.Kind == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "batch.run.kind is required")
		return
	}
	res, err := s.applyIngest(r.Context(), userFrom(r.Context()), &b)
	if err != nil {
		s.log.Error("ingest/batch failed", "err", err, "user", userFrom(r.Context()))
		writeErr(w, http.StatusInternalServerError, "internal_error", "ingest failed")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleIngestFile(w http.ResponseWriter, r *http.Request) {
	fileType := r.URL.Query().Get("type")
	if fileType == "" {
		fileType = "auto"
	}
	switch fileType {
	case "auto", "nmap", "nxc", "gowitness", "nuclei":
	default:
		writeErr(w, http.StatusBadRequest, "invalid_request", "type must be auto|nmap|nxc|gowitness|nuclei")
		return
	}

	if err := r.ParseMultipartForm(1 << 20); err != nil {
		if isMaxBytes(err) {
			writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large", "file exceeds max_upload_mb")
			return
		}
		writeErr(w, http.StatusBadRequest, "bad_multipart", "expected a multipart form with one file")
		return
	}
	var file io.ReadCloser
	sourceName := ""
	for _, files := range r.MultipartForm.File {
		if len(files) > 0 {
			f, err := files[0].Open()
			if err != nil {
				writeErr(w, http.StatusBadRequest, "bad_multipart", "expected a multipart form with one file")
				return
			}
			file = f
			sourceName = files[0].Filename
			break
		}
	}
	if file == nil {
		writeErr(w, http.StatusBadRequest, "no_file", "no file field in the multipart form")
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		if isMaxBytes(err) {
			writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large", "file exceeds max_upload_mb")
			return
		}
		writeErr(w, http.StatusBadRequest, "bad_multipart", "reading the uploaded file failed")
		return
	}

	var b *ingest.Batch
	switch fileType {
	case "nxc":
		writeErr(w, http.StatusBadRequest, "needs_filename",
			"NetExec DBs are identified by their protocol file name (smb.db, …); upload via the web import page or `cork push`")
		return
	case "gowitness":
		b, err = gowitness.Parse(bytes.NewReader(data))
	case "nuclei":
		b, err = nuclei.Parse(bytes.NewReader(data))
	default:
		if fileType == "auto" {
			b, err = parseAuto(data)
		} else {
			b, err = nmap.Parse(bytes.NewReader(data))
		}
	}
	if err != nil {
		if fileType == "auto" {
			writeErr(w, http.StatusBadRequest, "undetectable",
				"can't tell what this is: "+err.Error())
		} else {
			writeErr(w, http.StatusBadRequest, "parse_error", err.Error())
		}
		return
	}

	sum := sha256.Sum256(data)
	b.Run.SourceSHA = hex.EncodeToString(sum[:])
	b.Run.SourceName = sourceName
	b.Run.Vantage = r.URL.Query().Get("vantage")

	res, err := s.applyIngest(r.Context(), userFrom(r.Context()), b)
	if err != nil {
		s.log.Error("ingest/file failed", "err", err, "user", userFrom(r.Context()))
		writeErr(w, http.StatusInternalServerError, "internal_error", "ingest failed")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func parseAuto(data []byte) (*ingest.Batch, error) {
	trimmed := bytes.TrimLeft(data, " \t\r\n\xef\xbb\xbf")
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<nmaprun")) {
		return nmap.Parse(bytes.NewReader(data))
	}
	if gowitness.Detect(data) {
		return gowitness.Parse(bytes.NewReader(data))
	}
	if nuclei.Detect(data) {
		return nuclei.Parse(bytes.NewReader(data))
	}
	return nil, fmt.Errorf("unrecognized input; upload nmap XML, gowitness JSONL, or nuclei JSONL")
}

func (s *Server) applyIngest(ctx context.Context, user string, b *ingest.Batch) (ingest.Result, error) {
	res, err := s.store.ApplyBatch(ctx, user, b)
	if err != nil {
		return res, err
	}
	if ids := res.TouchedHostIDs(); len(ids) > 0 {
		sc := s.Scope()
		out, err := s.store.ApplyScopeZones(ctx,
			func(ip string, hostnames []string) string { return string(sc.ZoneOfIP(ip, hostnames)) },
			user, ids)
		if err != nil {
			return res, err
		}
		res.OutOfScope = out
	}
	return res, nil
}

func (s *Server) writeDecodeErr(w http.ResponseWriter, err error) {
	if errors.Is(err, errBodyTooLarge) {
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds max_upload_mb")
		return
	}
	writeErr(w, http.StatusBadRequest, "bad_json", "malformed JSON body")
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		if isMaxBytes(err) {
			return errBodyTooLarge
		}
		return errBadJSON
	}
	return nil
}

func hostsFilter(q map[string][]string) (store.HostFilter, error) {
	var f store.HostFilter
	var err error
	get := func(key string) string {
		if v := q[key]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	f.Q = get("q")
	f.Tag = get("tag")
	f.Status = get("status")
	f.Zone = get("zone")
	f.Owner = get("owner")
	f.Service = get("service")
	f.Sort = get("sort")
	if f.Sort != "" && f.Sort != "ip" && f.Sort != "priority" && f.Sort != "last_seen" {
		return f, fmt.Errorf("sort must be ip|priority|last_seen")
	}
	if p := get("port"); p != "" {
		f.Port, err = strconv.Atoi(p)
		if err != nil || f.Port < 1 || f.Port > 65535 {
			return f, fmt.Errorf("port must be an integer in 1-65535")
		}
	}
	if l := get("limit"); l != "" {
		f.Limit, err = strconv.Atoi(l)
		if err != nil || f.Limit < 1 || f.Limit > 5000 {
			return f, fmt.Errorf("limit must be an integer in 1-5000")
		}
	}
	switch get("has_cred") {
	case "":
	case "1", "true":
		f.HasCred = true
	default:
		return f, fmt.Errorf("has_cred must be 1 or true")
	}
	return f, nil
}

func writeFilterErr(w http.ResponseWriter, err error) {
	writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	f, err := hostsFilter(r.URL.Query())
	if err != nil {
		writeFilterErr(w, err)
		return
	}
	hosts, err := s.store.ListHosts(r.Context(), f)
	if err != nil {
		s.log.Error("list hosts", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "listing hosts failed")
		return
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetHost(r.Context(), r.PathValue("ip"))
	if err != nil {
		s.hostErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) hostErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrUnknownHost):
		writeErr(w, http.StatusNotFound, "not_found", "unknown host")
	case errors.Is(err, store.ErrAlreadyClaimed):
		writeErr(w, http.StatusConflict, "already_claimed", err.Error())
	case errors.Is(err, store.ErrHostLocked):
		writeErr(w, http.StatusConflict, "host_locked", err.Error())
	case errors.Is(err, store.ErrNotOwner):
		writeErr(w, http.StatusConflict, "not_owner", err.Error())
	default:
		s.log.Error("host endpoint", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "request failed")
	}
}

func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Steal bool `json:"steal"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if err := s.store.ClaimHost(r.Context(), r.PathValue("ip"), userFrom(r.Context()), body.Steal); err != nil {
		s.hostErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ReleaseHost(r.Context(), r.PathValue("ip"), userFrom(r.Context())); err != nil {
		s.hostErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	err := s.store.SetStatus(r.Context(), r.PathValue("ip"), userFrom(r.Context()), body.Status, body.Reason)
	if err != nil {
		if errors.Is(err, store.ErrUnknownHost) {
			s.hostErr(w, err)
			return
		}

		writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleNote(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Body    string `json:"body"`
		Port    int    `json:"port"`
		Proto   string `json:"proto"`
		Outcome string `json:"outcome"`
		Command string `json:"command"`
		Output  string `json:"output"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	err := s.store.AddLog(r.Context(), r.PathValue("ip"), userFrom(r.Context()), store.LogInput{
		Port: body.Port, Proto: body.Proto, Body: body.Body, Outcome: body.Outcome, Command: body.Command, Output: body.Output,
	})
	switch {
	case errors.Is(err, store.ErrInvalidInput):
		writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	case errors.Is(err, store.ErrUnknownService):
		writeErr(w, http.StatusNotFound, "unknown_service", err.Error())
		return
	case err != nil:
		s.hostErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Add    []string `json:"add"`
		Remove []string `json:"remove"`
	}
	if err := decodeOptionalJSON(r, &body); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if err := s.store.SetTags(r.Context(), r.PathValue("ip"), userFrom(r.Context()), body.Add, body.Remove); err != nil {
		s.hostErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f, err := hostsFilter(q)
	if err != nil {
		writeFilterErr(w, err)
		return
	}
	format := q.Get("format")
	if format == "" {
		format = "ip"
	}
	hosts, err := s.store.ListHosts(r.Context(), f)
	if err != nil {
		s.log.Error("list targets", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "listing targets failed")
		return
	}

	var sb strings.Builder
	switch format {
	case "ip", "hostport":
		for _, h := range hosts {
			line := h.IP
			if format == "hostport" && f.Port > 0 {
				line += ":" + strconv.Itoa(f.Port)
			}
			sb.WriteString(line)
			sb.WriteByte('\n')
		}
	case "url":
		for _, h := range hosts {
			sb.WriteString(targetURL(h.IP, f.Port))
			sb.WriteByte('\n')
		}
	case "nmap":

		for i, h := range hosts {
			if i > 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(h.IP)
		}
	default:
		writeErr(w, http.StatusBadRequest, "invalid_request", "format must be ip|hostport|url|nmap")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, sb.String())
}

func targetURL(ip string, port int) string {
	if port == 443 {
		return "https://" + ip + "/"
	}
	if port > 0 && port != 80 {
		return "http://" + ip + ":" + strconv.Itoa(port) + "/"
	}
	return "http://" + ip + "/"
}

func decodeOptionalJSON(r *http.Request, v any) error {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		if isMaxBytes(err) {
			return errBodyTooLarge
		}
		return errBadJSON
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, v); err != nil {
		return errBadJSON
	}
	return nil
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ScanHistory(r.Context(), r.URL.Query().Get("ip"))
	if err != nil {
		writeErr(w, 500, "internal_error", "listing scans failed")
		return
	}
	writeJSON(w, 200, rows)
}

func (s *Server) handlePriority(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Priority int `json:"priority"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	err := s.store.SetPriority(r.Context(), r.PathValue("ip"), userFrom(r.Context()), body.Priority)
	if errors.Is(err, store.ErrInvalidInput) {
		writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err != nil {
		s.hostErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "priority": body.Priority})
}

func (s *Server) handleServiceExplored(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid_request", "invalid service id")
		return
	}
	var body struct {
		Explored bool `json:"explored"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	err = s.store.SetServiceExplored(r.Context(), userFrom(r.Context()), id, body.Explored)
	if errors.Is(err, store.ErrUnknownService) {
		writeErr(w, http.StatusNotFound, "not_found", "unknown service")
		return
	}
	if err != nil {
		s.log.Error("service explored", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal_error", "request failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "explored": body.Explored})
}
