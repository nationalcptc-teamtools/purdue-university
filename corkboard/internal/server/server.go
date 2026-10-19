package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"corkboard/internal/auth"
	"corkboard/internal/bloodhound"
	"corkboard/internal/config"
	"corkboard/internal/events"
	"corkboard/internal/scope"
	"corkboard/internal/screenshots"
	"corkboard/internal/store"
	"corkboard/internal/web"
)

type Server struct {
	cfg     *config.Server
	store   *store.Store
	scope   atomic.Pointer[scope.Scope]
	dataDir string
	version string
	log     *slog.Logger

	pass  *auth.Verifier
	fails *auth.Limiter

	broker     *events.Broker
	web        *web.Web
	bh         *bloodhound.Service
	shotsMu    sync.Mutex
	snapshotMu sync.RWMutex
	configMu   sync.Mutex
	shots      *screenshots.Store
}

func (s *Server) shotsDir() string { return filepath.Join(s.dataDir, "screenshots") }

func New(cfg *config.Server, st *store.Store, sc *scope.Scope, dataDir, version string) *Server {
	s := &Server{
		cfg:     cfg,
		store:   st,
		dataDir: dataDir,
		version: version,
		log:     slog.New(slog.NewTextHandler(os.Stderr, nil)),
		fails:   auth.NewLimiter(),
	}
	if v, err := auth.NewVerifier(cfg.PassphraseHash); err != nil {
		s.log.Error("passphrase_hash unusable; all logins will fail", "err", err)
	} else {
		s.pass = v
	}
	s.scope.Store(sc)
	s.broker = events.NewBroker()
	s.bh = bloodhound.New(st, cfg.BloodHound)
	st.SetEventSink(s.broker)
	s.Web()
	return s
}

func (s *Server) checkPassphrase(p string) bool { return s.pass != nil && s.pass.Check(p) }

func (s *Server) DataDir() string { return s.dataDir }

func (s *Server) Scope() *scope.Scope { return s.scope.Load() }

func (s *Server) Web() *web.Web {
	if s.web == nil {
		w, err := web.New(web.Deps{
			Store:           s.store,
			BloodHound:      s.bh,
			Scope:           s.Scope,
			Broker:          s.broker,
			SessionSecret:   []byte(s.cfg.SessionSecret),
			EngagementName:  s.cfg.EngagementName,
			CheckPassphrase: s.checkPassphrase,
			Limiter:         s.fails,
			ArchiveExport:   s.browserArchiveExport,
			EvidenceUpload:  s.handleEvidenceUpload,
			EvidenceRead:    s.handleEvidenceRead,
			ArchiveInspect:  s.browserArchiveInspect,
			Ingest:          s.applyIngest,
			Logger:          s.log,
		})
		if err != nil {
			s.log.Error("web init", "err", err)
			return nil
		}
		s.web = w
	}
	return s.web
}

func (s *Server) SetLogger(l *slog.Logger) { s.log = l }

func (s *Server) Version() string { return s.version }

func (s *Server) Reload() error {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	data, err := os.ReadFile(filepath.Join(s.dataDir, "scope.yaml"))
	if err != nil {
		return err
	}
	sc, err := scope.Load(data)
	if err != nil {
		return err
	}
	s.scope.Store(sc)
	return nil
}

func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/v1/whoami", s.handleWhoami)
	api.HandleFunc("POST /api/v1/ingest/batch", s.handleIngestBatch)
	api.HandleFunc("POST /api/v1/ingest/file", s.handleIngestFile)
	api.HandleFunc("GET /api/v1/hosts", s.handleListHosts)
	api.HandleFunc("GET /api/v1/hosts/{ip}", s.handleGetHost)
	api.HandleFunc("POST /api/v1/hosts/{ip}/claim", s.handleClaim)
	api.HandleFunc("POST /api/v1/hosts/{ip}/release", s.handleRelease)
	api.HandleFunc("POST /api/v1/hosts/{ip}/status", s.handleStatus)
	api.HandleFunc("POST /api/v1/hosts/{ip}/priority", s.handlePriority)
	api.HandleFunc("POST /api/v1/services/{id}/explored", s.handleServiceExplored)
	api.HandleFunc("POST /api/v1/hosts/{ip}/owned", s.handleSetOwned)
	api.HandleFunc("POST /api/v1/hosts/{ip}/notes", s.handleNote)
	api.HandleFunc("POST /api/v1/hosts/{ip}/tags", s.handleTags)
	api.HandleFunc("GET /api/v1/targets", s.handleTargets)
	api.HandleFunc("GET /api/v1/checks", s.handleChecks)
	api.HandleFunc("POST /api/v1/checks/action", s.handleCheckAction)
	api.HandleFunc("POST /api/v1/checks/result", s.handleCheckResult)
	api.HandleFunc("GET /api/v1/checks/history", s.handleCheckHistory)
	api.HandleFunc("GET /api/v1/credential-profiles", s.handleCredentialProfiles)
	api.HandleFunc("POST /api/v1/credential-profiles", s.handleCredentialProfiles)
	api.HandleFunc("POST /api/v1/checks/applicability", s.handleApplicability)
	api.HandleFunc("GET /api/v1/access-observations", s.handleAccessObservations)
	api.HandleFunc("POST /api/v1/access-observations", s.handleAccessObservations)
	api.HandleFunc("PATCH /api/v1/applications/{id}", s.handlePatchApplication)
	api.HandleFunc("GET /api/v1/search", s.handleSearch)
	api.HandleFunc("GET /api/v1/claims", s.handleTargetClaims)
	api.HandleFunc("GET /api/v1/changes", s.handleChanges)
	api.HandleFunc("GET /api/v1/access", s.handleAccess)
	api.HandleFunc("POST /api/v1/access", s.handleAccess)
	api.HandleFunc("POST /api/v1/access/{id}/end", s.handleAccessEnd)
	api.HandleFunc("GET /api/v1/vantages", s.handleVantages)
	api.HandleFunc("POST /api/v1/vantages", s.handleVantages)
	api.HandleFunc("GET /api/v1/tunnels", s.handleTunnels)
	api.HandleFunc("POST /api/v1/tunnels", s.handleTunnels)
	api.HandleFunc("POST /api/v1/tunnels/{id}/end", s.handleTunnelEnd)
	api.HandleFunc("POST /api/v1/changes/ack", s.handleChangesAck)
	api.HandleFunc("POST /api/v1/claims", s.handleTargetClaims)
	api.HandleFunc("GET /api/v1/tasks", s.handleListTasks)
	api.HandleFunc("POST /api/v1/tasks", s.handleCreateTask)
	api.HandleFunc("PATCH /api/v1/tasks/{id}", s.handlePatchTask)
	api.HandleFunc("GET /api/v1/creds", s.handleListCreds)
	api.HandleFunc("GET /api/v1/findings", s.handleListFindings)
	api.HandleFunc("POST /api/v1/findings", s.handleCreateFinding)
	api.HandleFunc("GET /api/v1/findings/{id}", s.handleFindingDetail)
	api.HandleFunc("GET /api/v1/applications", s.handleApplications)
	api.HandleFunc("POST /api/v1/applications", s.handleApplications)
	api.HandleFunc("POST /api/v1/evidence", s.handleEvidenceUpload)
	api.HandleFunc("GET /api/v1/evidence/{id}", s.handleEvidenceRead)
	api.HandleFunc("PATCH /api/v1/findings/{id}", s.handlePatchFinding)
	api.HandleFunc("GET /api/v1/events", s.handleListEvents)
	api.HandleFunc("GET /api/v1/scans", s.handleListScans)
	api.HandleFunc("POST /api/v1/screenshots", s.handleScreenshotUpload)
	api.HandleFunc("POST /api/v1/creds", s.handleAddCred)
	api.HandleFunc("POST /api/v1/creds/{id}/access", s.handleAddCredAccess)
	api.HandleFunc("GET /api/v1/creds/{id}/reveal", s.handleRevealCred)
	api.HandleFunc("GET /api/v1/creds/matrix", s.handleCredMatrix)
	api.HandleFunc("GET /api/v1/export/{kind}", s.handleExport)
	api.HandleFunc("POST /api/v1/archive/export", s.handleArchiveExport)
	api.HandleFunc("POST /api/v1/archive/inspect", s.handleArchiveInspect)
	api.HandleFunc("GET /api/v1/bloodhound/status", s.handleBloodHoundStatus)
	api.HandleFunc("POST /api/v1/bloodhound/check", s.handleBloodHoundCheck)
	api.HandleFunc("POST /api/v1/bloodhound/targets", s.handleBloodHoundTarget)
	api.HandleFunc("POST /api/v1/bloodhound/sync", s.handleBloodHoundSync)
	api.HandleFunc("POST /api/v1/admin/purge", s.handlePurge)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /shots/", s.handleShotAuth)
	mux.Handle("/api/v1/", s.requireAuth(api))
	if w := s.Web(); w != nil {
		mux.Handle("/", w.Handler())
	}
	return s.chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		archiveRoute := r.URL.Path == "/api/v1/archive/export" || r.URL.Path == "/archive/export" || r.URL.Path == "/api/v1/archive/inspect" || r.URL.Path == "/archive/inspect"
		if r.Method != "GET" && r.Method != "HEAD" && !archiveRoute {
			s.snapshotMu.RLock()
			defer s.snapshotMu.RUnlock()
		}
		mux.ServeHTTP(w, r)
	}))
}

func (s *Server) Run() error {
	tlsCfg, err := s.tlsConfig()
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsCfg,
	}

	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Listen, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go s.bh.Run(ctx)
	defer s.bh.Stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	if d := s.cfg.BackupEvery.AsDuration(); d > 0 {
		go s.backupLoop(ctx, d)
	}
	s.startWebhookAlerts(ctx)
	errCh := make(chan error, 1)
	go func() {
		if tlsCfg != nil {
			errCh <- srv.ServeTLS(ln, "", "")
		} else {
			errCh <- srv.Serve(ln)
		}
	}()

	scheme := "http"
	if tlsCfg != nil {
		scheme = "https"
	}
	s.log.Info("listening", "scheme", scheme, "addr", s.cfg.Listen, "engagement", s.cfg.EngagementName)
	if host, _, err := net.SplitHostPort(s.cfg.Listen); err == nil && (host == "0.0.0.0" || host == "::") {
		s.log.Warn("binding to all interfaces: cork holds client credentials; prefer a private interface or Tailscale",
			"listen", s.cfg.Listen)
	}

	for {
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		case <-ctx.Done():
			s.bh.Stop()
			s.log.Info("shutting down")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return srv.Shutdown(shutdownCtx)
		case <-hup:
			if err := s.Reload(); err != nil {
				s.log.Error("reload failed; keeping old config", "err", err)
			} else {
				s.log.Info("config reloaded")
			}
		}
	}
}

func (s *Server) backupLoop(ctx context.Context, interval time.Duration) {
	dir := filepath.Join(s.dataDir, store.BackupDirName)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if p, err := s.store.Backup(dir); err != nil {
				s.log.Error("backup failed", "err", err)
			} else {
				s.log.Info("backup written", "file", p)
			}
		}
	}
}
