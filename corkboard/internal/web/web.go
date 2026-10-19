package web

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"corkboard/internal/auth"
	"corkboard/internal/bloodhound"
	"corkboard/internal/events"
	"corkboard/internal/scope"
	"corkboard/internal/store"
)

//go:embed assets
var assetsFS embed.FS

//go:embed templates/*.html
var tmplFS embed.FS

type Deps struct {
	Store           *store.Store
	BloodHound      *bloodhound.Service
	Scope           func() *scope.Scope
	Broker          *events.Broker
	SessionSecret   []byte
	EngagementName  string
	CheckPassphrase func(string) bool
	Limiter         *auth.Limiter
	Ingest          IngestFunc
	EvidenceUpload  http.HandlerFunc
	EvidenceRead    http.HandlerFunc
	ArchiveExport   http.HandlerFunc
	ArchiveInspect  http.HandlerFunc
	Logger          *slog.Logger
}

type Web struct {
	secret         []byte
	st             *store.Store
	broker         *events.Broker
	scopeFn        func() *scope.Scope
	engage         string
	passOK         func(string) bool
	tmpl           *template.Template
	log            *slog.Logger
	mux            *http.ServeMux
	limiter        *auth.Limiter
	bh             *bloodhound.Service
	evidenceUpload http.HandlerFunc
	evidenceRead   http.HandlerFunc
	archiveExport  http.HandlerFunc
	archiveInspect http.HandlerFunc
	ingest         IngestFunc
}

func New(d Deps) (*Web, error) {
	tmpl, err := template.New("").Funcs(funcMap()).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	if d.Limiter == nil {
		d.Limiter = auth.NewLimiter()
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.NewTextHandler(discardWriter{}, nil))
	}
	return &Web{
		secret:         d.SessionSecret,
		st:             d.Store,
		broker:         d.Broker,
		scopeFn:        d.Scope,
		engage:         d.EngagementName,
		passOK:         d.CheckPassphrase,
		tmpl:           tmpl,
		log:            d.Logger,
		limiter:        d.Limiter,
		bh:             d.BloodHound,
		ingest:         d.Ingest,
		evidenceUpload: d.EvidenceUpload, evidenceRead: d.EvidenceRead,
		archiveExport:  d.ArchiveExport,
		archiveInspect: d.ArchiveInspect,
	}, nil
}

func (w *Web) Handler() http.Handler {
	if w.mux == nil {
		m := http.NewServeMux()

		m.HandleFunc("GET /assets/", w.handleAssets)
		m.HandleFunc("POST /alarm/ack", w.webAction(w.alarmAck))
		m.HandleFunc("GET /login", w.handleLoginGET)
		m.HandleFunc("POST /login", w.handleLoginPOST)
		m.HandleFunc("POST /logout", w.handleLogout)

		m.HandleFunc("GET /events", w.handleEvents)

		m.HandleFunc("GET /", w.requireWeb(w.handleDashboard))
		m.HandleFunc("GET /hosts", w.requireWeb(w.handleHosts))
		m.HandleFunc("GET /hosts/{ip}", w.requireWeb(w.handleHost))
		m.HandleFunc("GET /checks", w.requireWeb(w.handleChecks))
		m.HandleFunc("POST /checks", w.requireWeb(w.handleChecksPOST))
		m.HandleFunc("GET /search", w.requireWeb(w.handleSearch))

		m.HandleFunc("GET /work", w.requireWeb(w.handleWork))
		m.HandleFunc("GET /tasks", w.requireWeb(w.handleTasks))
		m.HandleFunc("GET /creds", w.requireWeb(w.handleCreds))
		m.HandleFunc("GET /activity", w.requireWeb(w.handleActivity))
		m.HandleFunc("GET /web", w.requireWeb(w.handleWeb))
		m.HandleFunc("GET /findings/new", w.requireWeb(w.handleFindingNew))
		m.HandleFunc("POST /findings/new", w.requireWeb(w.handleFindingCreate))
		m.HandleFunc("GET /findings/{id}", w.requireWeb(w.handleFindingDetail))
		m.HandleFunc("POST /findings/{id}", w.requireWeb(w.handleFindingEdit))
		m.HandleFunc("POST /evidence", w.requireWeb(w.handleEvidenceUpload))
		m.HandleFunc("GET /evidence/{id}", w.requireWeb(w.handleEvidenceRead))
		m.HandleFunc("GET /findings", w.requireWeb(w.handleFindings))
		m.HandleFunc("POST /findings/{id}/state", w.webAction(w.handleFindingState))
		m.HandleFunc("GET /import", w.requireWeb(w.handleImport))
		m.HandleFunc("GET /archive", w.requireWeb(w.handleArchive))
		m.HandleFunc("POST /archive/export", w.requireWeb(w.handleArchiveExport))
		m.HandleFunc("POST /archive/inspect", w.requireWeb(w.handleArchiveInspect))

		m.HandleFunc("POST /import", w.requireWeb(w.handleImportPOST))
		m.HandleFunc("POST /tasks", w.requireWeb(w.handleTaskCreate))
		m.HandleFunc("POST /creds", w.requireWeb(w.handleCredAdd))
		m.HandleFunc("POST /creds/access", w.requireWeb(w.handleCredAccess))

		m.HandleFunc("POST /hosts/{ip}/claim", w.webAction(w.hostActionClaim))
		m.HandleFunc("POST /hosts/{ip}/release", w.webAction(w.hostActionRelease))
		m.HandleFunc("POST /hosts/{ip}/status", w.webAction(w.hostActionStatus))
		m.HandleFunc("POST /hosts/{ip}/priority", w.webAction(w.hostActionPriority))
		m.HandleFunc("POST /hosts/{ip}/services/{id}/explored", w.webAction(w.serviceActionExplored))
		m.HandleFunc("POST /hosts/{ip}/services/{id}/claim", w.webAction(w.serviceActionClaim))
		m.HandleFunc("POST /hosts/{ip}/notes", w.webAction(w.hostActionNote))
		m.HandleFunc("POST /hosts/{ip}/tags", w.webAction(w.hostActionTags))
		m.HandleFunc("POST /hosts/{ip}/owned", w.webAction(w.hostActionOwned))
		m.HandleFunc("POST /tasks/{id}/claim", w.webAction(w.taskActionClaim))
		m.HandleFunc("POST /tasks/{id}/release", w.webAction(w.taskActionRelease))
		m.HandleFunc("POST /tasks/{id}/done", w.webAction(w.taskActionDone))
		m.HandleFunc("POST /tasks/{id}/block", w.webAction(w.taskActionBlock))
		w.mux = m
	}
	return w.mux
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func partial(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

func hxRedirectBack(wr http.ResponseWriter, r *http.Request, fallback string) {
	ref := r.Header.Get("HX-Redirect")
	if ref == "" {
		ref = r.Referer()
	}
	if ref == "" {
		ref = fallback
	}
	http.Redirect(wr, r, ref, http.StatusSeeOther)
}

func (w *Web) render(wr http.ResponseWriter, r *http.Request, name string, data any) error {
	return w.tmpl.ExecuteTemplate(wr, name, data)
}

type baseData struct {
	User       string
	CSRF       string
	Engage     string
	Page       string
	Err        string
	LastSeenID int64
	Now        time.Time
}

func (w *Web) pageData(r *http.Request, page string) baseData {
	ls := int64(-1)
	if c, err := r.Cookie(lastSeenCookie); err == nil {
		ls, _ = strconv.ParseInt(c.Value, 10, 64)
	}
	return baseData{
		User:       w.User(r),
		CSRF:       w.CSRFToken(r),
		Engage:     w.engage,
		Page:       page,
		LastSeenID: ls,
		Now:        time.Now(),
	}
}
