package bloodhound

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"corkboard/internal/config"
	remote "corkboard/internal/integrations/bloodhound"
	"corkboard/internal/store"
)

var ErrDisabled = errors.New("BloodHound syncing is disabled; configure bloodhound in server.yaml or use the owned-identities export")
var ErrStopped = errors.New("BloodHound synchronization has stopped; restart Corkboard to enable it again")

type Remote interface {
	Check(context.Context) (remote.Info, error)
	SyncOwned(context.Context, string, string) (remote.Result, error)
	RequestAnalysis(context.Context) error
}

type Status struct {
	Enabled    bool                     `json:"enabled"`
	AutoSync   bool                     `json:"auto_sync"`
	URL        string                   `json:"url"`
	Configured bool                     `json:"configured"`
	Error      string                   `json:"error,omitempty"`
	LastError  string                   `json:"last_error,omitempty"`
	LastSyncAt int64                    `json:"last_sync_at,omitempty"`
	Version    string                   `json:"version,omitempty"`
	Mode       string                   `json:"mode,omitempty"`
	Targets    []store.BloodHoundTarget `json:"targets"`
}

type Service struct {
	st            *store.Store
	cfg           config.BloodHound
	wake          chan struct{}
	mu            sync.Mutex
	info          remote.Info
	lastError     string
	lastSync      int64
	syncMu        sync.Mutex
	lastTarget    int64
	passBudget    time.Duration
	targetTimeout time.Duration
	lifetime      context.Context
	stop          context.CancelFunc
	connect       func() (Remote, error)
}

func New(st *store.Store, cfg config.BloodHound) *Service {
	s := &Service{st: st, cfg: cfg, wake: make(chan struct{}, 1), passBudget: 30 * time.Second, targetTimeout: 10 * time.Second}
	s.lifetime, s.stop = context.WithCancel(context.Background())
	s.connect = func() (Remote, error) {
		if !cfg.Enabled {
			return nil, ErrDisabled
		}
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		id, key := os.Getenv(cfg.TokenIDEnv), os.Getenv(cfg.TokenKeyEnv)
		if id == "" || key == "" {
			return nil, fmt.Errorf("BloodHound API credentials are missing from the configured environment variables")
		}
		return remote.New(remote.Options{URL: cfg.URL, TokenID: id, TokenKey: key})
	}
	return s
}

func (s *Service) Stop() { s.stop() }

func (s *Service) workContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	stopWatch := context.AfterFunc(s.lifetime, cancel)
	if s.lifetime.Err() != nil {
		cancel()
	}
	return ctx, func() { stopWatch(); cancel() }
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	d := Status{Enabled: s.cfg.Enabled, AutoSync: s.cfg.AutoSync, URL: s.cfg.URL}

	if !d.Enabled {
		d.URL = ""
	}
	if d.Enabled {
		_, err := s.connect()
		d.Configured = err == nil
		if err != nil {
			d.Error = err.Error()
		}
	}
	var err error
	d.Targets, err = s.st.ListBloodHoundTargets(ctx)
	if err != nil {
		return d, err
	}
	for i := range d.Targets {
		ok, eligibleErr := s.eligible(ctx, d.Targets[i])
		if eligibleErr != nil {
			return d, eligibleErr
		}
		if !ok {
			d.Targets[i].State = "paused"
			d.Targets[i].Error = "Host is no longer compromised or in scope; ownership sync is paused."
		}
	}
	if d.Targets == nil {
		d.Targets = []store.BloodHoundTarget{}
	}
	s.mu.Lock()
	d.Version, d.Mode, d.LastError, d.LastSyncAt = s.info.Version, s.info.Mode, s.lastError, s.lastSync
	s.mu.Unlock()
	return d, err
}

func (s *Service) Check(ctx context.Context) (remote.Info, error) {
	if s.lifetime.Err() != nil {
		return remote.Info{}, ErrStopped
	}
	ctx, cancel := s.workContext(ctx)
	defer cancel()
	c, err := s.connect()
	var info remote.Info
	if err == nil {
		info, err = c.Check(ctx)
	}
	s.mu.Lock()
	if err != nil {
		s.lastError = err.Error()
	} else {
		s.info, s.lastError = info, ""
	}
	s.mu.Unlock()
	return info, err
}

func (s *Service) RequestSync(ctx context.Context) error {
	if s.lifetime.Err() != nil {
		return ErrStopped
	}
	if !s.cfg.Enabled {
		return ErrDisabled
	}
	if _, err := s.connect(); err != nil {
		return err
	}
	if err := s.st.PrepareBloodHoundTargets(ctx); err != nil {
		return err
	}
	if err := s.st.QueueBloodHoundTargets(ctx); err != nil {
		return err
	}
	s.Wake()
	return nil
}

func (s *Service) Wake() {
	if s.lifetime.Err() != nil {
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Service) WakeAuto() {
	if s.cfg.Enabled && s.cfg.AutoSync {
		s.Wake()
	}
}

func (s *Service) Run(ctx context.Context) {
	if !s.cfg.Enabled || s.lifetime.Err() != nil {
		return
	}
	ctx, cancel := s.workContext(ctx)
	defer cancel()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	if s.cfg.AutoSync {
		s.SyncOnce(ctx)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
			s.SyncOnce(ctx)
		case <-ticker.C:
			if s.cfg.AutoSync {
				s.SyncOnce(ctx)
			}
		}
	}
}

func (s *Service) SyncOnce(ctx context.Context) {
	if !s.cfg.Enabled || s.lifetime.Err() != nil || !s.syncMu.TryLock() {
		return
	}
	defer s.syncMu.Unlock()
	ctx, lifetimeCancel := s.workContext(ctx)
	defer lifetimeCancel()
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, s.passBudget)
	defer cancel()
	setError := func(err error) { s.mu.Lock(); s.lastError = err.Error(); s.mu.Unlock() }
	if err := s.st.PrepareBloodHoundTargets(ctx); err != nil {
		setError(err)
		return
	}
	rows, err := s.st.ListBloodHoundTargets(ctx)
	if err != nil {
		setError(err)
		return
	}
	c, err := s.connect()
	if err != nil {
		setError(err)
		return
	}

	for i, t := range rows {
		if t.ID == s.lastTarget {
			rows = append(rows[i+1:], rows[:i+1]...)
			break
		}
	}
	synced := 0
	for _, t := range rows {
		if ctx.Err() != nil {
			break
		}
		if t.State != "pending" && !(s.cfg.AutoSync && t.State == "error") {
			continue
		}
		eligible, err := s.eligible(ctx, t)
		if err != nil {

			if ctx.Err() != nil {
				break
			}
			setError(err)
			return
		}
		if !eligible {
			continue
		}
		s.lastTarget = t.ID
		targetCtx, targetCancel := context.WithTimeout(ctx, s.targetTimeout)
		result, syncErr := c.SyncOwned(targetCtx, t.Kind, t.Identity)
		targetCancel()
		errorText := ""
		if syncErr != nil {
			errorText = syncErr.Error()
			setError(syncErr)
		}

		persistCtx, persistCancel := context.WithTimeout(parent, 2*time.Second)
		err = s.st.FinishBloodHoundTarget(persistCtx, t.ID, t.Identity, result.ObjectID, result.Name, errorText)
		persistCancel()
		if err != nil {
			setError(err)
			return
		}
		if syncErr == nil {
			synced++
			s.mu.Lock()
			s.lastSync = time.Now().UnixMilli()
			s.info.Mode = result.Mode
			s.lastError = ""
			s.mu.Unlock()
		}
	}

	if synced > 0 {
		analysisCtx, analysisCancel := context.WithTimeout(parent, s.targetTimeout)
		if err := c.RequestAnalysis(analysisCtx); err != nil {
			setError(fmt.Errorf("owned selectors saved, but requesting BloodHound analysis failed: %w", err))
		}
		analysisCancel()
	}

	if parent.Err() == nil {
		pending, err := s.st.ListBloodHoundTargets(parent)
		if err != nil {
			setError(err)
			return
		}
		for _, t := range pending {
			if t.State != "pending" {
				continue
			}
			ok, err := s.eligible(parent, t)
			if err != nil {
				setError(err)
				return
			}
			if ok {
				s.Wake()
				break
			}
		}
	}
}

func (s *Service) eligible(ctx context.Context, t store.BloodHoundTarget) (bool, error) {
	if t.Kind == "User" {
		return true, nil
	}
	if t.Kind != "Computer" || t.HostID == nil || t.IP == "" {
		return false, nil
	}
	h, err := s.st.GetHost(ctx, t.IP)
	if err != nil {
		return false, err
	}
	return h.Host.Status == "compromised" && (h.Host.Zone == "in" || h.Host.Zone == "caution"), nil
}

func (s *Service) ExportOwned(ctx context.Context) (string, error) {
	rows, err := s.st.ListBloodHoundTargets(ctx)
	if err != nil {
		return "", err
	}
	seen := map[string]string{}
	mapped := map[int64]bool{}
	for _, t := range rows {
		ok, err := s.eligible(ctx, t)
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		seen[strings.ToUpper(t.Identity)] = t.Identity
		if t.HostID != nil {
			mapped[*t.HostID] = true
		}
	}
	hosts, err := s.st.ListExportHosts(ctx)
	if err != nil {
		return "", err
	}
	var skipped []string
	for _, h := range hosts {
		if h.Status != "compromised" || (h.Zone != "in" && h.Zone != "caution") || mapped[h.ID] {
			continue
		}
		detail, err := s.st.GetHost(ctx, h.IP)
		if err != nil {
			return "", err
		}
		identity := store.BloodHoundHostIdentity(detail.Host.Hostnames)
		if identity == "" {
			skipped = append(skipped, h.IP)
			continue
		}
		seen[strings.ToUpper(identity)] = identity
	}
	identities := make([]string, 0, len(seen))
	for _, name := range seen {
		identities = append(identities, name)
	}
	sort.Strings(identities)
	var b strings.Builder
	b.WriteString("# BloodHound owned identities — review and mark these in BloodHound CE.\n# Computers: compromised in-scope hosts. Users: explicitly recorded only. No secrets.\n")
	for _, name := range identities {
		b.WriteString(name + "\n")
	}
	for _, ip := range skipped {
		fmt.Fprintf(&b, "# Needs an explicit Computer identity: %s\n", ip)
	}
	return b.String(), nil
}
