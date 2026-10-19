package nxc

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	_ "modernc.org/sqlite"

	"corkboard/internal/ingest"
)

var Supported = []string{"smb", "ldap", "mssql", "winrm", "rdp", "ssh"}

func Protocol(fileName string) string {
	base := strings.ToLower(filepath.Base(fileName))
	if !strings.HasSuffix(base, ".db") {
		return ""
	}
	p := strings.TrimSuffix(base, ".db")
	for _, s := range Supported {
		if p == s {
			return s
		}
	}
	return ""
}

type Batch struct {
	*ingest.Batch
	Warnings []string
}

func ReadFile(ctx context.Context, path string) (*Batch, error) {
	proto := Protocol(filepath.Base(path))
	if proto == "" {
		return nil, fmt.Errorf("%s is not a supported NetExec protocol DB (supported: %s)",
			filepath.Base(path), strings.Join(Supported, ", "))
	}
	tmp, err := copySidecars(path)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(filepath.Dir(tmp))

	db, err := sql.Open("sqlite", "file:"+tmp+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	b, warns, err := parse(ctx, db, proto)
	if err != nil {
		return nil, err
	}
	return &Batch{Batch: b, Warnings: warns}, nil
}

func ReadWorkspace(ctx context.Context, dir string) ([]*Batch, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*Batch
	var ignored []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".db") {
			continue
		}
		if Protocol(e.Name()) == "" {
			ignored = append(ignored, e.Name())
			continue
		}
		b, err := ReadFile(ctx, filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no NetExec protocol DBs in %s", dir)
	}
	if len(ignored) > 0 {
		out[0].Warnings = append(out[0].Warnings,
			fmt.Sprintf("ignored unknown DB(s): %s", strings.Join(ignored, ", ")))
	}
	return out, nil
}

func copySidecars(path string) (string, error) {
	tmp, err := os.MkdirTemp("", "cork-nxc-*")
	if err != nil {
		return "", err
	}
	base := filepath.Base(path)
	files := []string{base}
	for _, sidecar := range []string{base + "-wal", base + "-shm"} {
		if st, err := os.Stat(filepath.Join(filepath.Dir(path), sidecar)); err == nil && st.Size() > 0 {
			files = append(files, sidecar)
		}
	}
	for _, f := range files {
		src, err := os.ReadFile(filepath.Join(filepath.Dir(path), f))
		if err != nil {
			os.RemoveAll(tmp)
			return "", err
		}
		if err := os.WriteFile(filepath.Join(tmp, f), src, 0o400); err != nil {
			os.RemoveAll(tmp)
			return "", err
		}
	}
	return filepath.Join(tmp, base), nil
}

func tableCols(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

var hex32 = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

func mapCredType(credtype, secret string) string {
	switch strings.ToLower(credtype) {
	case "plaintext":
		return "password"
	case "hash":
		if strings.Contains(secret, ":") || hex32.MatchString(secret) {
			return "ntlm"
		}
		return "other"
	case "key":
		return "ssh_key"
	default:
		return "other"
	}
}

func isHashLike(secret string) bool {
	if strings.Contains(secret, ":") {
		return true
	}
	if len(secret) != 32 {
		return false
	}
	_, err := hex.DecodeString(secret)
	return err == nil
}

func parse(ctx context.Context, db *sql.DB, proto string) (*ingest.Batch, []string, error) {
	var warns []string
	b := &ingest.Batch{
		Version: 1,
		Run: ingest.RunInfo{
			Kind:       "nxc",
			Protocol:   proto,
			SourceName: proto + ".db",
		},
	}
	hostIP, err := readHosts(ctx, db, proto, b, &warns)
	if err != nil {
		return nil, nil, err
	}
	if err := readUsers(ctx, db, proto, b, &warns); err != nil {
		return nil, nil, err
	}
	if err := readAccess(ctx, db, proto, b, hostIP, &warns); err != nil {
		return nil, nil, err
	}
	if proto == "smb" {
		if err := readShares(ctx, db, b, hostIP, &warns); err != nil {
			return nil, nil, err
		}
	}
	if len(b.Hosts) == 0 && len(b.Creds) == 0 {
		warns = append(warns, proto+".db: no usable hosts or credentials found")
	}
	return b, warns, nil
}

var hostOptionalCols = []struct{ col, key string }{
	{"hostname", ""}, {"domain", ""}, {"os", ""},
	{"dc", "dc"}, {"smbv1", "smbv1"}, {"signing", "smb_signing"},
	{"spooler", "spooler"}, {"zerologon", "zerologon"},
	{"petitpotam", "petitpotam"},
	{"signing_required", "ldap_signing"}, {"channel_binding", "ldap_channel_binding"},
	{"mssqlversion", "mssql_version"}, {"instances", "mssql_instances"},
	{"nla", "rdp_nla"},
}

var boolHostCols = map[string]bool{
	"dc": true, "smbv1": true, "signing": true, "spooler": true,
	"zerologon": true, "petitpotam": true, "signing_required": true,
	"channel_binding": true, "nla": true,
}

func readHosts(ctx context.Context, db *sql.DB, proto string, b *ingest.Batch, warns *[]string) (map[int64]string, error) {
	ipCol, idCol := "ip", "id"
	if proto == "ssh" {

		ipCol, idCol = "host", "rowid"
	}
	cols, err := tableCols(db, "hosts")
	if err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		*warns = append(*warns, "hosts table missing")
		return map[int64]string{}, nil
	}
	if !cols[ipCol] || (idCol != "rowid" && !cols[idCol]) {
		*warns = append(*warns, "hosts table missing "+idCol+"/"+ipCol+", skipping hosts")
		return map[int64]string{}, nil
	}

	sel := []string{idCol, ipCol}
	var opt []struct{ col, key string }
	for _, a := range hostOptionalCols {
		if cols[a.col] {
			sel = append(sel, a.col)
			opt = append(opt, a)
		}
	}
	rows, err := db.QueryContext(ctx, "SELECT "+strings.Join(sel, ", ")+" FROM hosts")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ipMap := map[int64]string{}
	for rows.Next() {
		var id int64
		var ip string
		rest := make([]any, len(opt))
		ptrs := make([]any, 0, len(opt)+2)
		ptrs = append(ptrs, &id, &ip)
		for i := range rest {
			ptrs = append(ptrs, &rest[i])
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		host := ingest.HostObs{IP: ip}
		for i, a := range opt {
			v := rest[i]
			switch a.col {
			case "hostname":
				if s := str(v); s != "" {
					host.Hostnames = append(host.Hostnames, ingest.NameObs{Name: s, Source: "nxc"})
				}
			case "domain":
				host.Domain = str(v)
			case "os":
				host.OS = str(v)
				if host.OS != "" {
					host.OSEvidence = append(host.OSEvidence, ingest.OSEvidence{Name: host.OS, Family: ingest.OSFamily(host.OS), Source: "nxc"})
				}
			default:
				s := attrValue(a.col, v)
				if s != "" {
					if host.Attrs == nil {
						host.Attrs = map[string]string{}
					}
					host.Attrs[a.key] = s
				}
			}
		}
		if ip != "" {
			ipMap[id] = ip
			b.Hosts = append(b.Hosts, host)
		} else {
			*warns = append(*warns, "hosts: row without IP, dropped")
		}
	}
	return ipMap, rows.Err()
}

func attrValue(col string, v any) string {
	if boolHostCols[col] {
		if asInt(v) == 1 {
			return "true"
		}
		return ""
	}
	return str(v)
}

func readUsers(ctx context.Context, db *sql.DB, proto string, b *ingest.Batch, warns *[]string) error {
	table := "users"
	if proto == "ssh" {
		table = "credentials"
	}
	cols, err := tableCols(db, table)
	if err != nil {
		return err
	}
	if len(cols) == 0 {
		*warns = append(*warns, table+" table missing")
		return nil
	}
	need := []string{"id", "username", "password", "credtype"}
	if proto != "ssh" {
		need = append(need, "domain")
	}
	for _, c := range need {
		if !cols[c] {
			*warns = append(*warns, table+"."+c+" column missing, skipping credentials")
			return nil
		}
	}
	q := "SELECT id, "
	if proto != "ssh" {
		q += "domain, "
	}
	q += "username, password, credtype FROM " + table
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var domain, user, secret, credtype string
		if proto != "ssh" {
			if err := rows.Scan(&id, &domain, &user, &secret, &credtype); err != nil {
				return err
			}
		} else if err := rows.Scan(&id, &user, &secret, &credtype); err != nil {
			return err
		}
		if secret == "" {
			continue
		}
		b.Creds = append(b.Creds, ingest.CredObs{
			Ref:        fmt.Sprintf("u:%d", id),
			Domain:     domain,
			Username:   user,
			Secret:     secret,
			SecretType: mapCredType(credtype, secret),
			Source:     "nxc",
		})
	}
	return rows.Err()
}

func readAccess(ctx context.Context, db *sql.DB, proto string, b *ingest.Batch, hostIP map[int64]string, warns *[]string) error {
	idCol := "userid"
	if proto == "ssh" {
		idCol = "credid"
	}
	for _, tbl := range []struct {
		table string
		level string
	}{
		{"admin_relations", "admin"},
		{"loggedin_relations", "valid"},
	} {
		cols, err := tableCols(db, tbl.table)
		if err != nil {
			return err
		}
		if len(cols) == 0 {
			*warns = append(*warns, tbl.table+" table missing")
			continue
		}
		if !cols[idCol] || !cols["hostid"] {
			*warns = append(*warns, tbl.table+" missing "+idCol+"/hostid, skipping")
			continue
		}
		rows, err := db.QueryContext(ctx, "SELECT "+idCol+", hostid FROM "+tbl.table)
		if err != nil {
			return err
		}
		for rows.Next() {
			var credID, hostID int64
			if err := rows.Scan(&credID, &hostID); err != nil {
				rows.Close()
				return err
			}
			ip, ok := hostIP[hostID]
			if !ok {
				*warns = append(*warns, fmt.Sprintf("%s: hostid %d not in hosts, dropped", tbl.table, hostID))
				continue
			}
			b.Access = append(b.Access, ingest.AccessObs{
				CredRef:  fmt.Sprintf("u:%d", credID),
				IP:       ip,
				Protocol: proto,
				Level:    tbl.level,
			})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	return nil
}

func readShares(ctx context.Context, db *sql.DB, b *ingest.Batch, hostIP map[int64]string, warns *[]string) error {
	cols, err := tableCols(db, "shares")
	if err != nil {
		return err
	}
	if len(cols) == 0 {
		*warns = append(*warns, "shares table missing")
		return nil
	}
	if !cols["hostid"] || !cols["name"] {
		*warns = append(*warns, "shares missing hostid/name, skipping")
		return nil
	}
	sel := []string{"hostid", "name"}
	idx := map[string]int{"hostid": 0, "name": 1}
	for _, c := range []string{"userid", "remark", "read", "write"} {
		if cols[c] {
			sel = append(sel, c)
			idx[c] = len(sel) - 1
		}
	}
	rows, err := db.QueryContext(ctx, "SELECT "+strings.Join(sel, ", ")+" FROM shares")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		vals := make([]any, len(sel))
		ptrs := make([]any, len(sel))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		s := ingest.ShareObs{
			IP:   hostIP[asInt(vals[idx["hostid"]])],
			Name: str(vals[idx["name"]]),
		}
		if i, ok := idx["userid"]; ok {
			s.CredRef = fmt.Sprintf("u:%d", asInt(vals[i]))
		}
		if i, ok := idx["remark"]; ok {
			s.Remark = str(vals[i])
		}
		if i, ok := idx["read"]; ok {
			s.Read = asInt(vals[i]) == 1
		}
		if i, ok := idx["write"]; ok {
			s.Write = asInt(vals[i]) == 1
		}
		if s.IP == "" || s.Name == "" {
			*warns = append(*warns, "shares: row with unknown host or empty name, dropped")
			continue
		}
		b.Shares = append(b.Shares, s)
	}
	return rows.Err()
}

func str(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	}
	return ""
}

func asInt(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	}
	return 0
}
