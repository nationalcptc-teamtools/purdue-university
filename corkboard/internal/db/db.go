package db

import (
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"database/sql"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func DSN(path string) string {
	return "file:" + path +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)"
}

type DB struct {
	Write       *sql.DB
	Read        *sql.DB
	Path        string
	txMu        sync.Mutex
	hooksMu     sync.Mutex
	commitHooks map[*sql.Tx][]func()
}

func Open(path string) (*DB, error) { return openSchema(path, 0) }

func OpenSchema(path string, version int) (*DB, error) {
	if version < 4 {
		return nil, fmt.Errorf("unsupported archive database schema %d", version)
	}
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	supported := false
	for _, entry := range entries {
		v, e := parseVersion(entry.Name())
		if e == nil && v == version {
			supported = true
		}
	}
	if !supported {
		return nil, fmt.Errorf("unsupported archive database schema %d; use a compatible newer cork binary", version)
	}
	return openSchema(path, version)
}

func openSchema(path string, version int) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	write, err := sql.Open("sqlite", DSN(path))
	if err != nil {
		return nil, err
	}
	write.SetMaxOpenConns(1)
	read, err := sql.Open("sqlite", DSN(path))
	if err != nil {
		write.Close()
		return nil, err
	}
	read.SetMaxOpenConns(8)
	d := &DB{Write: write, Read: read, Path: path}
	if err := d.migrateTo(context.Background(), version); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) Migrate(ctx context.Context) error { return d.migrateTo(ctx, 0) }

func (d *DB) migrateTo(ctx context.Context, maxVersion int) error {
	if _, err := d.Write.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("schema_migrations: %w", err)
	}
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		version, err := parseVersion(name)
		if err != nil {
			return err
		}
		if maxVersion > 0 && version > maxVersion {
			continue
		}
		var exists int
		if err := d.Write.QueryRowContext(ctx,
			`SELECT 1 FROM schema_migrations WHERE version = ?`, version).Scan(&exists); err == sql.ErrNoRows {

			stmt, err := migrationsFS.ReadFile("migrations/" + name)
			if err != nil {
				return err
			}
			tx, err := d.Write.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, string(stmt)); err != nil {
				tx.Rollback()
				return fmt.Errorf("migration %s: %w", name, err)
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
				version, nowMS()); err != nil {
				tx.Rollback()
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	return d.repairRunsVantage(ctx)
}

func (d *DB) repairRunsVantage(ctx context.Context) error {
	var applied int
	if err := d.Write.QueryRowContext(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version = 3`).Scan(&applied); err != nil || applied == 0 {
		return err
	}
	var has int
	if err := d.Write.QueryRowContext(ctx,
		`SELECT count(*) FROM pragma_table_info('runs') WHERE name = 'vantage'`).Scan(&has); err != nil || has > 0 {
		return err
	}
	if _, err := d.Write.ExecContext(ctx, `ALTER TABLE runs ADD COLUMN vantage TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("repair runs.vantage: %w", err)
	}
	return nil
}

func (d *DB) WithTx(ctx context.Context, fn func(*sql.Tx) error) error {

	d.txMu.Lock()
	defer d.txMu.Unlock()
	tx, err := d.Write.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	d.hooksMu.Lock()
	if d.commitHooks == nil {
		d.commitHooks = make(map[*sql.Tx][]func())
	}
	d.commitHooks[tx] = nil
	d.hooksMu.Unlock()
	defer func() {
		tx.Rollback()
		d.hooksMu.Lock()
		delete(d.commitHooks, tx)
		d.hooksMu.Unlock()
	}()
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	d.hooksMu.Lock()
	hooks := d.commitHooks[tx]
	delete(d.commitHooks, tx)
	d.hooksMu.Unlock()
	for _, hook := range hooks {
		hook()
	}
	return nil
}

func (d *DB) AfterCommit(tx *sql.Tx, fn func()) bool {
	d.hooksMu.Lock()
	defer d.hooksMu.Unlock()
	if _, ok := d.commitHooks[tx]; !ok {
		return false
	}
	d.commitHooks[tx] = append(d.commitHooks[tx], fn)
	return true
}

func (d *DB) Close() error {
	err := d.Write.Close()
	if err2 := d.Read.Close(); err == nil {
		err = err2
	}
	return err
}

func parseVersion(name string) (int, error) {
	v, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
	if err != nil {
		return 0, fmt.Errorf("migration %q: version must start with an integer", name)
	}
	return v, nil
}

func nowMS() int64 { return time.Now().UnixMilli() }
