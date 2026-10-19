package archive

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"corkboard/internal/accessgraph"
	"corkboard/internal/auth"
	"corkboard/internal/config"
	"corkboard/internal/db"
	"corkboard/internal/scope"
	"corkboard/internal/store"
)

const (
	FormatVersion       = 1
	MaxBytes      int64 = 32 << 30
	MaxFiles            = 100000
	maxManifest         = 32 << 20
)

var screenshotName = regexp.MustCompile(`^screenshots/([0-9a-f]{64})\.(png|jpg)$`)
var textEvidenceName = regexp.MustCompile(`^evidence/([0-9a-f]{64})\.txt$`)

var includeName = regexp.MustCompile(`^rules-includes/[0-9]{4,6}\.yaml$`)
var exportName = regexp.MustCompile(`^exports/([a-z_]+\.csv|access\.md|access-ledger\.json|access-graph\.svg)$`)

type File struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Format           int              `json:"format"`
	Schema           int              `json:"schema"`
	AppVersion       string           `json:"app_version"`
	EngagementID     string           `json:"engagement_uuid"`
	EngagementName   string           `json:"engagement_name"`
	SourceInstanceID string           `json:"source_instance_uuid"`
	SnapshotAt       time.Time        `json:"snapshot_at"`
	EventID          int64            `json:"high_water_event_id"`
	Counts           map[string]int64 `json:"counts"`
	EvidenceComplete bool             `json:"evidence_complete"`
	Files            map[string]File  `json:"files"`
}

type Source struct {
	DB             *db.DB
	Screenshots    string
	Scope          []byte
	EngagementName string
	AppVersion     string
}

type Snapshot struct {
	Dir      string
	Manifest Manifest
}

func (s *Snapshot) Close() error { return os.RemoveAll(s.Dir) }

func Capture(ctx context.Context, src Source) (_ *Snapshot, err error) {
	dir, err := os.MkdirTemp(filepath.Dir(src.DB.Path), ".cork-archive-")
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Dir: dir, Manifest: Manifest{Format: FormatVersion, AppVersion: src.AppVersion, EngagementName: src.EngagementName, SnapshotAt: time.Now().UTC(), Files: map[string]File{}}}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	dbPath := filepath.Join(dir, "engagement.db")
	if _, err = src.DB.Write.ExecContext(ctx, "VACUUM INTO ?", dbPath); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	if err = os.Chmod(dbPath, 0600); err != nil {
		return nil, err
	}
	frozen, err := openReadOnly(dbPath)
	if err != nil {
		return nil, err
	}
	defer frozen.Close()
	if err = metadata(ctx, frozen, &s.Manifest); err != nil {
		return nil, err
	}
	if _, err = scope.Load(src.Scope); err != nil {
		return nil, err
	}
	if err = writePrivate(dir, "scope.yaml", src.Scope); err != nil {
		return nil, err
	}
	refs, err := evidenceRefs(ctx, frozen)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, ref := range refs {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if !regexpHex(ref) {
			missing = append(missing, ref)
			continue
		}
		found := false
		for _, ext := range []string{"jpg", "png"} {
			name := "screenshots/" + ref + "." + ext
			source := filepath.Join(src.Screenshots, ref+"."+ext)
			info, e := os.Lstat(source)
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return nil, e
			}
			if !info.Mode().IsRegular() || info.Size() > 5<<20 {
				return nil, fmt.Errorf("invalid screenshot original %s", ref)
			}
			target := filepath.Join(dir, filepath.FromSlash(name))
			if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				return nil, err
			}

			if err = os.Link(source, target); err != nil {

				if err = copyFile(ctx, source, target); err != nil {
					return nil, err
				}
			}
			found = true
			break
		}
		if !found {
			missing = append(missing, ref)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing referenced screenshots (%d): %s", len(missing), strings.Join(missing, ", "))
	}
	if err = pinAttachments(ctx, frozen, src, dir); err != nil {
		return nil, err
	}
	s.Manifest.EvidenceComplete = true
	return s, nil
}

func (s *Snapshot) Pack(ctx context.Context, dst io.Writer) error {
	frozen, err := openReadOnly(filepath.Join(s.Dir, "engagement.db"))
	if err != nil {
		return err
	}
	err = companions(ctx, s.Dir, frozen, s.Manifest)
	frozen.Close()
	if err != nil {
		return err
	}
	var names []string
	err = filepath.WalkDir(s.Dir, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(s.Dir, p)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		item, err := hashFile(ctx, p)
		if err != nil {
			return err
		}
		if match := screenshotName.FindStringSubmatch(name); match != nil && item.SHA256 != match[1] {
			return fmt.Errorf("screenshot hash mismatch: %s", match[1])
		}
		if match := textEvidenceName.FindStringSubmatch(name); match != nil && (item.SHA256 != match[1] || item.Size > 65536) {
			return fmt.Errorf("invalid text evidence: %s", name)
		}
		s.Manifest.Files[name] = item
		names = append(names, name)
		return nil
	})
	if err != nil {
		return err
	}
	if len(names)+1 > MaxFiles {
		return fmt.Errorf("archive has too many files")
	}
	var total int64
	for _, f := range s.Manifest.Files {
		if f.Size > MaxBytes-total {
			return fmt.Errorf("archive exceeds 32 GiB expanded limit")
		}
		total += f.Size
	}
	data, err := json.MarshalIndent(s.Manifest, "", "  ")
	if err != nil {
		return err
	}
	if total+int64(len(data)) > MaxBytes {
		return fmt.Errorf("archive exceeds expanded size limit")
	}
	if len(data) > maxManifest {
		return fmt.Errorf("archive manifest exceeds 32 MiB limit")
	}
	if err = validateDatabase(ctx, s); err != nil {
		return err
	}
	zw := zip.NewWriter(&byteLimitWriter{w: dst, remaining: MaxBytes})
	add := func(name string, r io.Reader) error {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0600)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, contextReader{ctx, r})
		return err
	}
	if err = add("manifest.json", strings.NewReader(string(data))); err != nil {
		zw.Close()
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		f, e := os.Open(filepath.Join(s.Dir, filepath.FromSlash(name)))
		if e != nil {
			zw.Close()
			return e
		}
		err = add(name, f)
		f.Close()
		if err != nil {
			zw.Close()
			return err
		}
	}
	return zw.Close()
}

func Inspect(ctx context.Context, name string) (*Manifest, error) {
	s, err := unpack(ctx, name)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return &s.Manifest, nil
}

func Restore(ctx context.Context, name, destination, passphrase string) (*Manifest, error) {
	dest, err := filepath.Abs(destination)
	if err != nil {
		return nil, err
	}
	if _, err = os.Lstat(dest); err == nil {
		return nil, fmt.Errorf("destination already exists: %s", dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s, err := unpack(ctx, name)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	stage, err := os.MkdirTemp(filepath.Dir(dest), ".cork-restore-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	for n := range s.Manifest.Files {
		if n == "engagement.db" || n == "scope.yaml" || strings.HasPrefix(n, "screenshots/") || strings.HasPrefix(n, "evidence/") {
			target := n
			if n == "engagement.db" {
				target = "cork.db"
			}
			if err = copyFile(ctx, filepath.Join(s.Dir, filepath.FromSlash(n)), filepath.Join(stage, filepath.FromSlash(target))); err != nil {
				return nil, err
			}
		}
	}
	if err = auth.CheckPolicy(passphrase); err != nil {
		return nil, err
	}
	cfg := config.DefaultServer(s.Manifest.EngagementName)
	cfg.PassphraseHash, err = auth.Hash(passphrase)
	if err != nil {
		return nil, err
	}
	cfg.SessionSecret, err = config.GenerateSessionSecret()
	if err != nil {
		return nil, err
	}
	if err = cfg.Save(filepath.Join(stage, "server.yaml")); err != nil {
		return nil, err
	}
	restored, err := db.Open(filepath.Join(stage, "cork.db"))
	if err != nil {
		return nil, err
	}
	id, err := newUUID()
	if err == nil {
		_, err = restored.Write.ExecContext(ctx, `UPDATE meta SET value=? WHERE key='instance_uuid'`, id)
	}
	if err == nil {
		_, err = restored.Write.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	}
	closeErr := restored.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = publish(stage, dest); err != nil {
		return nil, err
	}
	return &s.Manifest, nil
}

func openReadOnly(p string) (*sql.DB, error) {
	absolute, err := filepath.Abs(p)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: absolute, RawQuery: "mode=ro&immutable=1&_pragma=trusted_schema(0)&_pragma=foreign_keys(1)"}
	d, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	return d, nil
}
func quote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
func metadata(ctx context.Context, d *sql.DB, m *Manifest) error {
	if err := d.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&m.Schema); err != nil {
		return err
	}
	if err := d.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='engagement_uuid'`).Scan(&m.EngagementID); err != nil {
		return err
	}
	if err := d.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='instance_uuid'`).Scan(&m.SourceInstanceID); err != nil {
		return err
	}
	if err := d.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0) FROM events`).Scan(&m.EventID); err != nil {
		return err
	}
	rows, err := d.QueryContext(ctx, `SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		if err = rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		names = append(names, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	m.Counts = map[string]int64{}
	for _, n := range names {
		var count int64
		if err = d.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quote(n)).Scan(&count); err != nil {
			return err
		}
		m.Counts[n] = count
	}
	return nil
}
func evidenceRefs(ctx context.Context, d *sql.DB) ([]string, error) {
	rows, err := d.QueryContext(ctx, `SELECT DISTINCT screenshot FROM web_results WHERE screenshot IS NOT NULL AND screenshot<>'' ORDER BY screenshot`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var refs []string
	for rows.Next() {
		var ref string
		if err = rows.Scan(&ref); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}
func regexpHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func writePrivate(dir, name string, data []byte) error {
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0600)
}
func copyFile(ctx context.Context, src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, contextReader{ctx, in})
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func hashFile(ctx context.Context, p string) (File, error) {
	f, err := os.Open(p)
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx, f})
	return File{Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, err
}

type byteLimitWriter struct {
	w         io.Writer
	remaining int64
}

func (w *byteLimitWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, fmt.Errorf("compressed archive exceeds 32 GiB limit")
	}
	n, err := w.w.Write(p)
	w.remaining -= int64(n)
	return n, err
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func allowed(name string) bool {
	return name == "engagement.db" || name == "scope.yaml" || name == "rules.yaml" || name == "index.html" || name == "verification.txt" || includeName.MatchString(name) || screenshotName.MatchString(name) || textEvidenceName.MatchString(name) || exportName.MatchString(name)
}
func unpack(ctx context.Context, name string) (_ *Snapshot, err error) {
	zr, err := zip.OpenReader(name)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	if len(zr.File) > MaxFiles {
		return nil, fmt.Errorf("archive has too many files")
	}
	info, err := os.Stat(name)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxBytes {
		return nil, fmt.Errorf("archive exceeds 32 GiB upload limit")
	}
	entries := map[string]*zip.File{}
	var total uint64
	for _, f := range zr.File {
		if f.Name != path.Clean(f.Name) || strings.ContainsAny(f.Name, "\\:\x00") || strings.HasPrefix(f.Name, "/") || f.Name == ".." || strings.HasPrefix(f.Name, "../") || !f.Mode().IsRegular() {
			return nil, fmt.Errorf("unsafe archive entry %q", f.Name)
		}
		if _, ok := entries[f.Name]; ok {
			return nil, fmt.Errorf("duplicate archive entry %q", f.Name)
		}
		if f.Name != "manifest.json" && !allowed(f.Name) {
			return nil, fmt.Errorf("unexpected archive entry %q", f.Name)
		}
		if f.UncompressedSize64 > uint64(MaxBytes)-total {
			return nil, fmt.Errorf("archive exceeds expanded size limit")
		}
		total += f.UncompressedSize64
		entries[f.Name] = f
	}
	mf, ok := entries["manifest.json"]
	if !ok || mf.UncompressedSize64 > maxManifest {
		return nil, fmt.Errorf("missing or oversized manifest")
	}
	r, err := mf.Open()
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(r, maxManifest+1))
	r.Close()
	if err != nil {
		return nil, err
	}
	if len(data) > maxManifest {
		return nil, fmt.Errorf("oversized manifest")
	}
	var m Manifest
	if err = json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.Format != FormatVersion {
		return nil, fmt.Errorf("unsupported archive format %d (supported %d)", m.Format, FormatVersion)
	}
	if !m.EvidenceComplete || m.EngagementName == "" || m.EngagementID == "" || m.SourceInstanceID == "" {
		return nil, fmt.Errorf("incomplete archive manifest")
	}
	if len(m.Files) != len(entries)-1 {
		return nil, fmt.Errorf("manifest entry count mismatch")
	}
	for _, required := range []string{"engagement.db", "scope.yaml", "index.html", "verification.txt"} {
		if _, ok = m.Files[required]; !ok {
			return nil, fmt.Errorf("missing required file %s", required)
		}
	}
	dir, err := os.MkdirTemp("", "cork-inspect-")
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Dir: dir, Manifest: m}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	for n, item := range m.Files {
		f, ok := entries[n]
		if !ok || !allowed(n) || item.Size < 0 || uint64(item.Size) != f.UncompressedSize64 || !regexpHex(item.SHA256) {
			return nil, fmt.Errorf("invalid manifest file %q", n)
		}
		if textEvidenceName.MatchString(n) && (item.Size > 65536 || textEvidenceName.FindStringSubmatch(n)[1] != item.SHA256) {
			return nil, fmt.Errorf("invalid text evidence %s", n)
		}
		if screenshotName.MatchString(n) && (item.Size > 5<<20 || screenshotName.FindStringSubmatch(n)[1] != item.SHA256) {
			return nil, fmt.Errorf("invalid screenshot entry %s", n)
		}
		r, e := f.Open()
		if e != nil {
			return nil, e
		}
		p := filepath.Join(dir, filepath.FromSlash(n))
		if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			r.Close()
			return nil, e
		}
		out, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			r.Close()
			return nil, e
		}
		h := sha256.New()
		written, e := io.Copy(io.MultiWriter(out, h), contextReader{ctx, io.LimitReader(r, item.Size+1)})
		r.Close()
		ce := out.Close()
		if e != nil {
			return nil, e
		}
		if ce != nil {
			return nil, ce
		}
		if written != item.Size || hex.EncodeToString(h.Sum(nil)) != item.SHA256 {
			return nil, fmt.Errorf("hash/size mismatch: %s", n)
		}
	}
	if err = validateDatabase(ctx, s); err != nil {
		return nil, err
	}
	scopeData, err := os.ReadFile(filepath.Join(dir, "scope.yaml"))
	if err != nil {
		return nil, err
	}
	if _, err = scope.Load(scopeData); err != nil {
		return nil, err
	}
	return s, nil
}

func validateDatabase(ctx context.Context, s *Snapshot) error {
	frozen, err := openReadOnly(filepath.Join(s.Dir, "engagement.db"))
	if err != nil {
		return err
	}
	defer frozen.Close()

	referenceDir, err := os.MkdirTemp("", "cork-schema-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(referenceDir)
	reference, err := db.OpenSchema(filepath.Join(referenceDir, "reference.db"), s.Manifest.Schema)
	if err != nil {
		return err
	}
	defer reference.Close()
	actual, err := schema(ctx, frozen)
	if err != nil {
		return err
	}
	expected, err := schema(ctx, reference.Read)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("unsupported or modified database schema (archive schema %d)", s.Manifest.Schema)
	}
	var version int
	if err = reference.Read.QueryRowContext(ctx, "SELECT MAX(version) FROM schema_migrations").Scan(&version); err != nil {
		return err
	}
	var migrationCount int
	if err = frozen.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version BETWEEN 1 AND ?", version).Scan(&migrationCount); err != nil {
		return err
	}
	if migrationCount != version || s.Manifest.Counts["schema_migrations"] != int64(version) {
		return fmt.Errorf("invalid database migration history")
	}
	if s.Manifest.Schema != version {
		return fmt.Errorf("unsupported database schema %d (supported %d)", s.Manifest.Schema, version)
	}
	rows, err := frozen.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return err
	}
	for rows.Next() {
		var result string
		if err = rows.Scan(&result); err != nil {
			rows.Close()
			return err
		}
		if result != "ok" {
			rows.Close()
			return fmt.Errorf("database integrity check failed")
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = frozen.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	bad := rows.Next()
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if bad {
		return fmt.Errorf("database foreign key check failed")
	}
	var derived Manifest
	if err = metadata(ctx, frozen, &derived); err != nil {
		return err
	}
	if derived.Schema != s.Manifest.Schema || derived.EngagementID != s.Manifest.EngagementID || derived.SourceInstanceID != s.Manifest.SourceInstanceID || derived.EventID != s.Manifest.EventID || !reflect.DeepEqual(derived.Counts, s.Manifest.Counts) {
		return fmt.Errorf("database metadata does not match manifest")
	}
	refs, err := evidenceRefs(ctx, frozen)
	if err != nil {
		return err
	}
	for _, ref := range refs {
		if !regexpHex(ref) {
			return fmt.Errorf("unresolved screenshot reference %q", ref)
		}
		_, jpg := s.Manifest.Files["screenshots/"+ref+".jpg"]
		_, png := s.Manifest.Files["screenshots/"+ref+".png"]
		if !jpg && !png {
			return fmt.Errorf("missing referenced screenshot %s", ref)
		}
	}
	attachments, err := attachmentNames(ctx, frozen)
	if err != nil {
		return err
	}
	for _, name := range attachments {
		if _, ok := s.Manifest.Files[name]; !ok {
			return fmt.Errorf("missing referenced attachment %s", name)
		}
	}
	return nil
}
func schema(ctx context.Context, d *sql.DB) (map[string]string, error) {
	rows, err := d.QueryContext(ctx, `SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY type,name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var typ, n, sql string
		if err = rows.Scan(&typ, &n, &sql); err != nil {
			return nil, err
		}
		out[typ+":"+n] = sql
	}
	return out, rows.Err()
}

func companions(ctx context.Context, dir string, d *sql.DB, m Manifest) error {
	var names []string
	for n := range m.Counts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if !exportName.MatchString("exports/" + n + ".csv") {
			return fmt.Errorf("unsupported table name %q", n)
		}
		rows, err := d.QueryContext(ctx, "SELECT * FROM "+quote(n))
		if err != nil {
			return err
		}
		cols, err := rows.Columns()
		if err != nil {
			rows.Close()
			return err
		}
		p := filepath.Join(dir, "exports", n+".csv")
		if err = os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			rows.Close()
			return err
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			rows.Close()
			return err
		}
		cw := csv.NewWriter(f)
		err = cw.Write(cols)
		for err == nil && rows.Next() {
			values := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err = rows.Scan(ptrs...); err != nil {
				break
			}
			record := make([]string, len(cols))
			for i, v := range values {
				if n == "creds" && cols[i] == "secret" {
					record[i] = "********"
				} else {
					switch v := v.(type) {
					case nil:
					case []byte:
						record[i] = string(v)
					default:
						record[i] = fmt.Sprint(v)
					}
				}
			}
			err = cw.Write(record)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		cw.Flush()
		if err == nil {
			err = cw.Error()
		}
		ce := f.Close()
		if err != nil {
			return err
		}
		if ce != nil {
			return ce
		}
	}
	if err := accessExports(ctx, dir, d); err != nil {
		return err
	}
	t := template.Must(template.New("index").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Corkboard snapshot</title><h1>{{.EngagementName}}</h1><p>Snapshot: {{.SnapshotAt}}. Engagement: {{.EngagementID}}. Event watermark: {{.EventID}}.</p><p>All referenced screenshots included. The database preserves credentials; readable credentials are masked.</p><p><a href="verification.txt">Verification details</a></p><h2>Access history</h2><ul><li><a href="exports/access.md">Chronological ledger (Markdown)</a></li><li><a href="exports/access-graph.svg">Access graph (SVG, first 150 edges)</a></li><li><a href="exports/access-ledger.json">Full ledger (JSON)</a></li></ul><h2>Tables</h2><ul>{{range $name,$count := .Counts}}<li><a href="exports/{{$name}}.csv">{{$name}}</a>: {{$count}} rows</li>{{end}}</ul></html>`))
	f, err := os.OpenFile(filepath.Join(dir, "index.html"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	err = t.Execute(f, m)
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	return writePrivate(dir, "verification.txt", []byte(fmt.Sprintf("Corkboard archive format %d; schema %d; app %s\nEngagement %s\nSnapshot %s\nHigh-water event %d\nAll referenced evidence included. Per-file SHA-256 hashes and sizes are in manifest.json.\nRun cork archive inspect FILE to verify hashes, database integrity, relationships and compatibility.\nHashes detect corruption, not malicious authorship.\n", m.Format, m.Schema, m.AppVersion, m.EngagementID, m.SnapshotAt.Format(time.RFC3339Nano), m.EventID)))
}

func PublishFile(src, dst string) error {

	return os.Link(src, dst)
}

func accessExports(ctx context.Context, dir string, d *sql.DB) error {
	edges, err := store.New(&db.DB{Read: d, Write: d}).Ledger(ctx, store.LedgerFilter{Derived: true})
	if err != nil {
		return err
	}
	ledger, err := json.MarshalIndent(map[string]any{"edges": edges}, "", "  ")
	if err != nil {
		return err
	}
	for name, body := range map[string][]byte{
		"access.md":          accessgraph.Markdown("Access history", edges),
		"access-graph.svg":   accessgraph.Build(edges).SVG("Access history", false, true),
		"access-ledger.json": ledger,
	} {
		if err := os.WriteFile(filepath.Join(dir, "exports", name), body, 0600); err != nil {
			return err
		}
	}
	return nil
}
