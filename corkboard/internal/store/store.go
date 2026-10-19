package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"corkboard/internal/db"
	"corkboard/internal/events"
	"corkboard/internal/model"
)

const (
	EventIngest           = "ingest"
	EventHostNew          = "host_new"
	EventServiceNew       = "service_new"
	EventClaim            = "claim"
	EventRelease          = "release"
	EventSteal            = "steal"
	EventTaskState        = "task_state"
	EventNote             = "note"
	EventCredNew          = "cred_new"
	EventCredAccessAdmin  = "cred_access_admin"
	EventCredReveal       = "cred_reveal"
	EventCompromise       = "compromise"
	EventFindingState     = "finding_state"
	EventScopeAlarm       = "scope_alarm"
	EventLockChange       = "lock_change"
	EventServiceExplored  = "service_explored"
	EventPriority         = "priority"
	EventRulesReload      = "rules_reload"
	EventStale            = "stale"
	EventExportSecrets    = "export_secrets"
	EventPurge            = "purge"
	EventBloodHoundTarget = "bloodhound_target"
	EventBloodHoundSync   = "bloodhound_sync"
)

var accessRank = map[string]int{"invalid": 0, "valid": 1, "admin": 2}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type Store struct {
	db     *db.DB
	now    func() int64
	events *events.Broker
}

func New(d *db.DB) *Store {
	return &Store{db: d, now: func() int64 { return time.Now().UnixMilli() }}
}

func (s *Store) SetNowFunc(f func() int64) { s.now = f }

func (s *Store) SetEventSink(b *events.Broker) { s.events = b }

func (s *Store) DB() *db.DB { return s.db }

func (s *Store) nowMS() int64 { return s.now() }

func (s *Store) appendEvent(ctx context.Context, e execer, at int64, actor, kind string, hostID, refID *int64, summary, data string) error {
	if e == s.db.Write {
		return s.db.WithTx(ctx, func(tx *sql.Tx) error {
			return s.appendEvent(ctx, tx, at, actor, kind, hostID, refID, summary, data)
		})
	}
	res, err := e.ExecContext(ctx,
		`INSERT INTO events (at, actor, kind, host_id, ref_id, summary, data)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		at, actor, kind, hostID, refID, summary, data)
	if err != nil {
		return err
	}
	if s.events != nil {
		id, _ := res.LastInsertId()
		event := model.Event{
			ID: id, At: at, Actor: actor, Kind: kind,
			HostID: cloneID(hostID), RefID: cloneID(refID), Summary: summary, Data: data,
		}
		tx, ok := e.(*sql.Tx)
		if !ok || !s.db.AfterCommit(tx, func() { s.events.Publish(event) }) {
			return fmt.Errorf("event transaction is not managed by WithTx")
		}
	}
	return nil
}

func cloneID(id *int64) *int64 {
	if id == nil {
		return nil
	}
	v := *id
	return &v
}

func jsonOr(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func (s *Store) GetMeta(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.Read.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	return v, err
}

func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.db.Write.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
