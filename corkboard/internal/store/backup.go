package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"corkboard/internal/model"
)

const BackupDirName = "backups"

const KeepBackups = 12

func (s *Store) Backup(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := "cork-" + time.Now().UTC().Format("20060102T150405.000Z") + ".db"
	dbPath := filepath.Join(dir, name)
	if _, err := s.db.Write.Exec("VACUUM INTO ?", dbPath); err != nil {
		return "", fmt.Errorf("vacuum into: %w", err)
	}
	stamp := strings.TrimSuffix(name, ".db")
	hosts, err := s.ListExportHosts(context.Background())
	if err != nil {
		return dbPath, err
	}
	if err := writeHostsCSV(filepath.Join(dir, stamp+".hosts.csv"), hosts); err != nil {
		return dbPath, err
	}
	creds, err := s.ListCreds(context.Background())
	if err != nil {
		return dbPath, err
	}
	if err := writeCredsCSVMasked(filepath.Join(dir, stamp+".creds.csv"), creds); err != nil {
		return dbPath, err
	}
	if _, err := RotateBackups(dir, KeepBackups); err != nil {
		return dbPath, err
	}
	return dbPath, nil
}

func RotateBackups(dir string, keep int) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var dbs []string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && strings.HasPrefix(n, "cork-") && strings.HasSuffix(n, ".db") {
			dbs = append(dbs, n)
		}
	}
	sort.Strings(dbs)
	if len(dbs) <= keep {
		return nil, nil
	}
	var removed []string
	for _, n := range dbs[:len(dbs)-keep] {
		stamp := strings.TrimSuffix(n, ".db")
		for _, f := range []string{n, stamp + ".hosts.csv", stamp + ".creds.csv"} {
			if err := os.Remove(filepath.Join(dir, f)); err != nil && !os.IsNotExist(err) {
				return removed, err
			}
		}
		removed = append(removed, n)
	}
	return removed, nil
}

func writeHostsCSV(path string, hosts []ExportHost) error {
	var b strings.Builder
	b.WriteString("ip,hostname,os,status,zone\n")
	for _, h := range hosts {
		var hn string
		for _, x := range h.HostnameList {
			if hn != "" {
				hn += ";"
			}
			hn += x
		}
		b.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s\n", h.IP, hn, h.OS, h.Status, h.Zone))
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func writeCredsCSVMasked(path string, creds []model.Cred) error {
	var b strings.Builder
	b.WriteString("user,secret,type\n")
	for _, c := range creds {
		b.WriteString(fmt.Sprintf("%s,********,%s\n", c.Username, c.SecretType))
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
