package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"corkboard/internal/ingest"
	"corkboard/internal/ingest/gowitness"
	"corkboard/internal/ingest/nmap"
	"corkboard/internal/ingest/nuclei"
	"corkboard/internal/ingest/nxc"
	"corkboard/internal/store"
)

type IngestFunc func(ctx context.Context, user string, b *ingest.Batch) (ingest.Result, error)

var notices = map[string]string{
	"task-created":   "Task created.",
	"task-exists":    "A task with that title already exists on this host.",
	"cred-added":     "Credential added.",
	"access-added":   "Access recorded.",
	"import-done":    "Import complete.",
	"import-already": "This file was already imported; nothing changed.",
}

var formErrors = map[string]string{
	"task-invalid": "Task not created: a title is required and priority must be 1–5.",
	"task-failed":  "Task not created. Check the server log.",
}

func noticeFrom(r *http.Request) string { return notices[r.URL.Query().Get("notice")] }

func formErrorFrom(r *http.Request) string { return formErrors[r.URL.Query().Get("error")] }

type importData struct {
	baseData
	Notice string
	Type   string
	Result *importResult
}

type importResult struct {
	File      string
	Kind      string
	Duplicate bool
	ingest.Result
}

func (w *Web) handleImport(wr http.ResponseWriter, r *http.Request) {
	w.renderImport(wr, r, http.StatusOK, importData{Type: "auto"})
}

func (w *Web) renderImport(wr http.ResponseWriter, r *http.Request, code int, d importData) {
	errMsg := d.Err
	d.baseData = w.pageData(r, "import")
	d.Err = errMsg
	if d.Err == "" && d.Result == nil {
		d.Notice = noticeFrom(r)
	}
	wr.Header().Set("Content-Type", "text/html; charset=utf-8")
	wr.WriteHeader(code)
	if err := w.render(wr, r, "import", d); err != nil {
		w.log.Error("render import", "err", err)
	}
}

func (w *Web) handleImportPOST(wr http.ResponseWriter, r *http.Request) {

	if err := r.ParseMultipartForm(1 << 20); err != nil && isTooLarge(err) {
		w.renderImport(wr, r, http.StatusRequestEntityTooLarge,
			importData{Type: "auto", baseData: baseData{Err: "That file is larger than the server's max_upload_mb."}})
		return
	}
	if !w.checkCSRF(wr, r) {
		http.Error(wr, "csrf check failed", http.StatusForbidden)
		return
	}
	d := importData{Type: r.FormValue("type")}
	fail := func(code int, msg string) {
		d.Err = msg
		w.renderImport(wr, r, code, d)
	}
	switch d.Type {
	case "auto", "nmap", "nxc", "gowitness", "nuclei":
	default:
		d.Type = "auto"
		fail(http.StatusBadRequest, "Choose a file type: auto, nmap, nxc, gowitness, or nuclei.")
		return
	}
	if w.ingest == nil {
		fail(http.StatusServiceUnavailable, "Importing is not available on this server.")
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		if isTooLarge(err) {
			fail(http.StatusRequestEntityTooLarge, "That file is larger than the server's max_upload_mb.")
			return
		}
		fail(http.StatusBadRequest, "Choose a file to import.")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		if isTooLarge(err) {
			fail(http.StatusRequestEntityTooLarge, "That file is larger than the server's max_upload_mb.")
			return
		}
		fail(http.StatusBadRequest, "Reading the upload failed.")
		return
	}
	name := filepath.Base(strings.ReplaceAll(hdr.Filename, `\`, "/"))
	b, warns, err := parseUpload(r.Context(), d.Type, name, data)
	if err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	sum := sha256.Sum256(data)
	b.Run.SourceName = name
	b.Run.SourceSHA = hex.EncodeToString(sum[:])
	user := w.User(r)
	res, err := w.ingest(r.Context(), user, b)
	if err != nil {
		w.log.Error("web import", "err", err, "user", user, "file", name)
		fail(http.StatusInternalServerError, "Import failed. Check the server log.")
		return
	}
	res.Warnings = append(warns, res.Warnings...)
	d.Result = &importResult{File: name, Kind: b.Run.Kind, Duplicate: res.Duplicate, Result: res}
	if res.Duplicate {
		d.Notice = notices["import-already"]
	} else {
		d.Notice = notices["import-done"]
	}
	w.renderImport(wr, r, http.StatusOK, d)
}

func parseUpload(ctx context.Context, kind, name string, data []byte) (*ingest.Batch, []string, error) {
	if kind == "auto" {
		kind = detectUpload(name, data)
		if kind == "" {
			return nil, nil, fmt.Errorf("Can't tell what %s is. Upload Nmap/masscan XML, a NetExec protocol DB (%s.db), or gowitness/nuclei JSONL.",
				name, strings.Join(nxc.Supported, ".db, "))
		}
	}
	switch kind {
	case "nmap":
		b, err := nmap.Parse(bytes.NewReader(data))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %v", name, err)
		}
		return b, nil, nil
	case "gowitness":
		b, err := gowitness.Parse(bytes.NewReader(data))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %v", name, err)
		}
		return b, nil, nil
	case "nuclei":
		b, err := nuclei.Parse(bytes.NewReader(data))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %v", name, err)
		}
		return b, nil, nil
	case "nxc":
		if nxc.Protocol(name) == "" {
			return nil, nil, fmt.Errorf("NetExec DBs must keep their protocol file name (%s.db); got %s.",
				strings.Join(nxc.Supported, ".db, "), name)
		}
		dir, err := os.MkdirTemp("", "cork-upload-")
		if err != nil {
			return nil, nil, err
		}
		defer os.RemoveAll(dir)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			return nil, nil, err
		}
		nb, err := nxc.ReadFile(ctx, p)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %v", name, err)
		}
		return nb.Batch, nb.Warnings, nil
	}
	return nil, nil, fmt.Errorf("unknown file type %q", kind)
}

func detectUpload(name string, data []byte) string {
	trimmed := bytes.TrimLeft(data, " \t\r\n\xef\xbb\xbf")
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<nmaprun")) {
		return "nmap"
	}
	if bytes.HasPrefix(data, []byte("SQLite format 3\x00")) && nxc.Protocol(name) != "" {
		return "nxc"
	}
	if gowitness.Detect(data) {
		return "gowitness"
	}
	if nuclei.Detect(data) {
		return "nuclei"
	}
	return ""
}

func isTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe) || errors.Is(err, multipart.ErrMessageTooLarge)
}

type taskForm struct {
	IP       string
	Port     string
	Title    string
	Body     string
	Commands string
	Priority string
}

func (w *Web) handleTaskCreate(wr http.ResponseWriter, r *http.Request) {
	if !w.checkCSRF(wr, r) {
		http.Error(wr, "csrf check failed", http.StatusForbidden)
		return
	}
	f := taskForm{
		IP:       strings.TrimSpace(r.FormValue("ip")),
		Port:     strings.TrimSpace(r.FormValue("port")),
		Title:    strings.TrimSpace(r.FormValue("title")),
		Body:     strings.TrimSpace(r.FormValue("body")),
		Commands: r.FormValue("commands"),
		Priority: r.FormValue("priority"),
	}
	fromHost := r.FormValue("from") == "host"
	fail := func(msg string) {
		if fromHost {

			key := "task-invalid"
			if !strings.HasPrefix(msg, "Host IP") && !strings.HasPrefix(msg, "Priority") {
				key = "task-failed"
			}
			http.Redirect(wr, r, "/hosts/"+url.PathEscape(f.IP)+"?error="+key+"#tasks", http.StatusSeeOther)
			return
		}
		w.renderTasks(wr, r, http.StatusUnprocessableEntity, f, msg)
	}
	if f.IP == "" || f.Title == "" {
		fail("Host IP and title are required.")
		return
	}
	prio := 3
	if f.Priority != "" {
		n, err := strconv.Atoi(f.Priority)
		if err != nil || n < 1 || n > 5 {
			fail("Priority must be 1–5.")
			return
		}
		prio = n
	}
	h, err := w.st.GetHost(r.Context(), f.IP)
	if errors.Is(err, store.ErrUnknownHost) {
		fail(fmt.Sprintf("No host %s in Corkboard yet. Import a scan that includes it first.", f.IP))
		return
	}
	if err != nil {
		w.log.Error("web task create", "err", err)
		fail("Looking up the host failed.")
		return
	}
	var cmds []string
	for _, line := range strings.Split(f.Commands, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			cmds = append(cmds, line)
		}
	}
	hostID := h.Host.ID
	var serviceID *int64
	if v := r.FormValue("service"); v != "" {
		for _, sv := range h.Services {
			if strconv.FormatInt(sv.ID, 10) == v {
				serviceID = &sv.ID
			}
		}
		if serviceID == nil {
			fail("That service is not on this host.")
			return
		}
	} else if f.Port != "" {
		port, proto, ok := parsePortProto(f.Port)
		if !ok {
			fail("Port must be a number like 445, or 161/udp.")
			return
		}
		for _, sv := range h.Services {
			if sv.Port == port && sv.Proto == proto {
				serviceID = &sv.ID
			}
		}
		if serviceID == nil {
			fail(fmt.Sprintf("%s has no %d/%s service in Corkboard. Leave Port empty for a whole-host task.", f.IP, port, proto))
			return
		}
	}
	_, created, err := w.st.CreateTask(r.Context(), w.User(r), store.NewTask{
		DedupeKey: store.ManualTaskKey(hostID, serviceID, f.Title),
		HostID:    &hostID,
		ServiceID: serviceID,
		Title:     f.Title,
		Body:      f.Body,
		Commands:  cmds,
		Priority:  prio,
	})
	if err != nil {
		w.log.Error("web task create", "err", err)
		fail("Creating the task failed.")
		return
	}
	notice := "task-created"
	if !created {
		notice = "task-exists"
	}
	if fromHost {
		http.Redirect(wr, r, "/hosts/"+url.PathEscape(h.Host.IP)+"?notice="+notice+"#tasks", http.StatusSeeOther)
		return
	}
	http.Redirect(wr, r, "/tasks?notice="+notice, http.StatusSeeOther)
}

type credForm struct {
	Domain     string
	Username   string
	SecretType string
	Notes      string
	IP         string
	Protocol   string
	Level      string
}

type accessForm struct {
	CredID   string
	IP       string
	Protocol string
	Level    string
}

func (w *Web) handleCredAdd(wr http.ResponseWriter, r *http.Request) {
	if !w.checkCSRF(wr, r) {
		http.Error(wr, "csrf check failed", http.StatusForbidden)
		return
	}
	f := credForm{
		Domain:     strings.TrimSpace(r.FormValue("domain")),
		Username:   strings.TrimSpace(r.FormValue("username")),
		SecretType: r.FormValue("secret_type"),
		Notes:      strings.TrimSpace(r.FormValue("notes")),
		IP:         strings.TrimSpace(r.FormValue("ip")),
		Protocol:   r.FormValue("protocol"),
		Level:      r.FormValue("level"),
	}
	secret := r.FormValue("secret")
	fail := func(msg string) {
		w.renderCreds(wr, r, http.StatusUnprocessableEntity, credsForms{Cred: f, CredErr: msg})
	}
	if f.Username == "" || secret == "" {
		fail("Username and secret are required.")
		return
	}
	if !store.ValidSecretType(f.SecretType) {
		fail("Choose a secret type.")
		return
	}
	in := store.CredInput{Domain: f.Domain, Username: f.Username, Secret: secret, SecretType: f.SecretType, Notes: f.Notes}
	if f.IP != "" {
		if !validIP(f.IP) {
			fail(f.IP + " is not a valid IP address.")
			return
		}
		if !store.ValidAccessProtocol(f.Protocol) || !store.ValidAccessLevel(f.Level) {
			fail("Choose a protocol and access level for the host.")
			return
		}
		in.Access = []store.CredAccessInput{{IP: f.IP, Protocol: f.Protocol, Level: f.Level}}
	}
	if _, err := w.st.AddCred(r.Context(), w.User(r), in); err != nil {

		fail(capitalize(err.Error()) + ".")
		return
	}
	http.Redirect(wr, r, "/creds?notice=cred-added", http.StatusSeeOther)
}

func (w *Web) handleCredAccess(wr http.ResponseWriter, r *http.Request) {
	if !w.checkCSRF(wr, r) {
		http.Error(wr, "csrf check failed", http.StatusForbidden)
		return
	}
	f := accessForm{
		CredID:   r.FormValue("cred"),
		IP:       strings.TrimSpace(r.FormValue("ip")),
		Protocol: r.FormValue("protocol"),
		Level:    r.FormValue("level"),
	}
	fail := func(msg string) {
		w.renderCreds(wr, r, http.StatusUnprocessableEntity, credsForms{Access: f, AccessErr: msg})
	}
	id, err := strconv.ParseInt(f.CredID, 10, 64)
	if err != nil || f.IP == "" {
		fail("Choose a credential and enter a host IP.")
		return
	}
	if !validIP(f.IP) {
		fail(f.IP + " is not a valid IP address.")
		return
	}
	if !store.ValidAccessProtocol(f.Protocol) || !store.ValidAccessLevel(f.Level) {
		fail("Choose a protocol and access level.")
		return
	}
	if err := w.st.AddCredAccess(r.Context(), w.User(r), id, f.IP, f.Protocol, f.Level); err != nil {
		switch {
		case errors.Is(err, store.ErrUnknownCred):
			fail("That credential no longer exists.")
		default:
			w.log.Error("web cred access", "err", err)
			fail("Recording access failed.")
		}
		return
	}
	http.Redirect(wr, r, "/creds?notice=access-added", http.StatusSeeOther)
}

func validIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func parsePortProto(v string) (int, string, bool) {
	proto := "tcp"
	if i := strings.Index(v, "/"); i >= 0 {
		v, proto = v[:i], strings.ToLower(v[i+1:])
	}
	port, err := strconv.Atoi(v)
	if err != nil || port < 1 || port > 65535 || (proto != "tcp" && proto != "udp") {
		return 0, "", false
	}
	return port, proto, true
}
