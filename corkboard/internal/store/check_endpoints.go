package store

import (
	"context"
	"corkboard/internal/ingest"
	"database/sql"
	"fmt"
	"strings"
)

func ensureCredentialProfiles(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO credential_profiles(cred_id,scope_kind,scope_value,updated_at) SELECT id,CASE WHEN domain<>'' AND domain<>'.' THEN 'domain' ELSE 'unknown' END,lower(domain),added_at FROM creds`)
	return err
}
func authenticationProtocol(port int, name, transport string) string {
	if transport != "tcp" && !(transport == "udp" && port == 88) {
		return ""
	}
	switch strings.ToLower(name) {
	case "http", "https", "ssl/http", "http-proxy":
		return ""
	case "ssh":
		return "ssh"
	case "microsoft-ds", "netbios-ssn", "smb":
		return "smb"
	case "ldap", "ldaps", "globalcatLDAP", "globalcatLDAPssl":
		return "ldap"
	case "ms-wbt-server", "rdp":
		return "rdp"
	case "ms-sql-s", "mssql":
		return "mssql"
	case "wsman", "winrm":
		return "winrm"
	case "kerberos-sec", "kerberos":
		return "kerberos"
	case "ftp":
		return "ftp"
	case "mysql":
		return "mysql"
	case "postgresql":
		return "postgres"
	}
	switch port {
	case 22:
		return "ssh"
	case 139, 445:
		return "smb"
	case 3389:
		return "rdp"
	case 5985, 5986:
		return "winrm"
	case 389, 636, 3268, 3269:
		return "ldap"
	case 1433:
		return "mssql"
	case 88:
		return "kerberos"
	case 21:
		return "ftp"
	case 3306:
		return "mysql"
	case 5432:
		return "postgres"
	}
	return ""
}
func (s *Store) syncEndpoint(ctx context.Context, tx *sql.Tx, ref TargetRef, protocol, vantage, identity, state, user string, occurred *int64, identityAt int64) error {
	if state != "open" && state != "closed" {
		return nil
	}
	tid, err := targetTx(ctx, tx, ref)
	if err != nil {
		return err
	}
	var id, gen, oldIdentityAt int64
	var oldState, oldIdentity string
	err = tx.QueryRowContext(ctx, `SELECT id,generation,state,identity,identity_at FROM auth_endpoints WHERE target_id=? AND protocol=? AND vantage=?`, tid, protocol, vantage).Scan(&id, &gen, &oldState, &oldIdentity, &oldIdentityAt)
	reason := "new endpoint"
	switch {
	case err == sql.ErrNoRows:
		if state == "closed" {
			return nil
		}
		res, e := tx.ExecContext(ctx, `INSERT INTO auth_endpoints(target_id,protocol,vantage,identity,state,changed_at,identity_at) VALUES(?,?,?,?,?,?,?)`, tid, protocol, vantage, identity, state, s.nowMS(), identityAt)
		if e != nil {
			return e
		}
		id, _ = res.LastInsertId()
		gen = 1
	case err != nil:
		return err
	default:
		if oldIdentity != identity && (identityAt == 0 || identityAt < oldIdentityAt) {
			identity = oldIdentity
			identityAt = oldIdentityAt
		}
		if identityAt < oldIdentityAt {
			identityAt = oldIdentityAt
		}
		if oldState == state && oldIdentity == identity {
			if identityAt > oldIdentityAt {
				_, err = tx.ExecContext(ctx, "UPDATE auth_endpoints SET identity_at=? WHERE id=?", identityAt, id)
				return err
			}
			return nil
		}
		reason = "service closed"
		if oldState == "closed" && state == "open" {
			gen++
			reason = "service reopened"
		} else if oldIdentity != identity {
			gen++
			reason = "authentication identity changed"
		}
		if _, err = tx.ExecContext(ctx, `UPDATE auth_endpoints SET generation=?,state=?,identity=?,changed_at=?,identity_at=? WHERE id=?`, gen, state, identity, s.nowMS(), identityAt, id); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO endpoint_history(endpoint_id,generation,state,identity,reason,occurred_at,recorded_at) VALUES(?,?,?,?,?,?,?)`, id, gen, state, identity, reason, occurred, s.nowMS()); err != nil {
		return err
	}
	var hid *int64
	if err = tx.QueryRowContext(ctx, "SELECT host_id FROM target_details WHERE id=?", tid).Scan(&hid); err != nil {
		return err
	}
	return s.appendEvent(ctx, tx, s.nowMS(), user, "endpoint_changed", hid, &id, reason, jsonOr(map[string]any{"endpoint_id": id, "generation": gen, "state": state, "vantage": vantage, "occurred_at": occurred}))
}
func (s *Store) syncAuthHosts(ctx context.Context, tx *sql.Tx, hosts []int64, reported map[int64]string, user string, identityAt int64) error {
	if err := ensureCredentialProfiles(ctx, tx); err != nil {
		return err
	}
	if len(hosts) == 0 {
		return nil
	}
	args := make([]any, len(hosts))
	for i, h := range hosts {
		args[i] = h
	}
	rows, err := tx.QueryContext(ctx, `SELECT s.id,h.id,s.port,COALESCE(s.name,''),COALESCE(h.domain,''),COALESCE(v.vantage,''),COALESCE(v.state,s.state),s.proto FROM services s JOIN hosts h ON h.id=s.host_id LEFT JOIN service_views v ON v.host_id=s.host_id AND v.proto=s.proto AND v.port=s.port WHERE h.id IN (`+placeholders(len(hosts))+`)`, args...)
	if err != nil {
		return err
	}
	type ep struct {
		id, host                                int64
		port                                    int
		name, domain, vantage, state, transport string
	}
	var all []ep
	for rows.Next() {
		var e ep
		if err = rows.Scan(&e.id, &e.host, &e.port, &e.name, &e.domain, &e.vantage, &e.state, &e.transport); err != nil {
			rows.Close()
			return err
		}
		all = append(all, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	type priorEndpoint struct {
		protocol, vantage, identity string
		at                          int64
		service                     int64
	}
	previous := map[string][]priorEndpoint{}
	oldRows, err := tx.QueryContext(ctx, `SELECT t.service_id,e.protocol,e.vantage,e.identity,e.identity_at FROM auth_endpoints e JOIN work_targets t ON t.id=e.target_id JOIN services s ON s.id=t.service_id WHERE e.state='open' AND s.host_id IN (`+placeholders(len(hosts))+`)`, args...)
	if err != nil {
		return err
	}
	for oldRows.Next() {
		var old priorEndpoint
		if err = oldRows.Scan(&old.service, &old.protocol, &old.vantage, &old.identity, &old.at); err != nil {
			oldRows.Close()
			return err
		}
		key := fmt.Sprintf("%d:%s", old.service, old.vantage)
		previous[key] = append(previous[key], old)
	}
	err = oldRows.Err()
	oldRows.Close()
	if err != nil {
		return err
	}
	for _, e := range all {
		protocol := authenticationProtocol(e.port, e.name, e.transport)
		if e.state == "open" || e.state == "closed" {
			for _, old := range previous[fmt.Sprintf("%d:%s", e.id, e.vantage)] {
				if old.protocol != protocol && (e.state == "closed" || (identityAt > 0 && identityAt >= old.at)) {
					if err = s.syncEndpoint(ctx, tx, TargetRef{"service", e.id}, old.protocol, e.vantage, old.identity, "closed", user, nil, identityAt); err != nil {
						return err
					}
				}
			}
		}
		if protocol == "" {
			continue
		}
		domain := e.domain
		if d := reported[e.host]; d != "" {
			domain = d
		}
		if err = s.syncEndpoint(ctx, tx, TargetRef{"service", e.id}, protocol, e.vantage, strings.ToLower(domain), e.state, user, nil, identityAt); err != nil {
			return err
		}
	}
	rows, err = tx.QueryContext(ctx, `SELECT a.id,a.origin,a.realm,a.retired FROM applications a LEFT JOIN services s ON s.id=a.service_id WHERE COALESCE(a.host_id,s.host_id) IN (`+placeholders(len(hosts))+`)`, args...)
	if err != nil {
		return err
	}
	type app struct {
		id            int64
		origin, realm string
		retired       bool
	}
	var apps []app
	for rows.Next() {
		var a app
		if err = rows.Scan(&a.id, &a.origin, &a.realm, &a.retired); err != nil {
			rows.Close()
			return err
		}
		apps = append(apps, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, a := range apps {
		state := "open"
		if a.retired {
			state = "closed"
		}
		if err = s.syncEndpoint(ctx, tx, TargetRef{"application", a.id}, "web", "", a.origin+"|"+a.realm, state, user, nil, s.nowMS()); err != nil {
			return err
		}
	}
	return nil
}

type CredentialProfile struct {
	CredID      int64    `json:"cred_id"`
	Identity    string   `json:"identity"`
	SecretType  string   `json:"secret_type"`
	Retired     bool     `json:"retired"`
	ScopeKind   string   `json:"scope_kind"`
	ScopeValue  string   `json:"scope_value"`
	Protocols   []string `json:"protocols"`
	RevisionOf  *int64   `json:"revision_of"`
	CrackedFrom *int64   `json:"cracked_from"`
}

func (s *Store) SetCredentialProfile(ctx context.Context, user string, p CredentialProfile) error {
	switch p.ScopeKind {
	case "unknown", "domain", "local", "target", "all":
	default:
		return fmt.Errorf("invalid credential scope")
	}
	if len(p.ScopeValue) > 512 {
		return fmt.Errorf("scope value too long")
	}
	if p.ScopeKind != "all" && p.ScopeKind != "unknown" && strings.TrimSpace(p.ScopeValue) == "" {
		return fmt.Errorf("scope value required")
	}
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		if err := ensureCredentialProfiles(ctx, tx); err != nil {
			return err
		}
		for _, protocol := range p.Protocols {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM credential_support s JOIN creds c ON c.secret_type=s.secret_type WHERE c.id=? AND s.protocol=?`, p.CredID, protocol).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("credential type does not support %s", protocol)
			}
		}
		if p.CrackedFrom != nil {
			var kind string
			if err := tx.QueryRowContext(ctx, "SELECT secret_type FROM creds WHERE id=?", *p.CrackedFrom).Scan(&kind); err != nil {
				return err
			}
			if kind != "hash_uncracked" || *p.CrackedFrom == p.CredID {
				return fmt.Errorf("cracked_from must reference a different uncracked hash")
			}
		}
		if p.RevisionOf != nil {
			next := p.RevisionOf
			for n := 0; next != nil; n++ {
				if n >= 32 || *next == p.CredID {
					return fmt.Errorf("credential revision cycle or chain too long")
				}
				var parent *int64
				if err := tx.QueryRowContext(ctx, "SELECT revision_of FROM credential_profiles WHERE cred_id=?", *next).Scan(&parent); err != nil {
					return err
				}
				next = parent
			}
		}
		protocols := "[]"
		if len(p.Protocols) > 0 {
			protocols = jsonOr(p.Protocols)
		}
		res, err := tx.ExecContext(ctx, `UPDATE credential_profiles SET retired=?,scope_kind=?,scope_value=?,protocols=?,revision_of=COALESCE(?,revision_of),cracked_from=COALESCE(?,cracked_from),updated_at=? WHERE cred_id=?`, p.Retired, p.ScopeKind, strings.ToLower(strings.TrimSpace(p.ScopeValue)), protocols, p.RevisionOf, p.CrackedFrom, s.nowMS(), p.CredID)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrUnknownCred
		}
		return s.appendEvent(ctx, tx, s.nowMS(), user, "credential_scope", nil, &p.CredID, "credential applicability updated", jsonOr(p))
	})
}
func (s *Store) SetCheckApplicability(ctx context.Context, user string, cred, endpoint int64, decision, reason string) error {
	if (decision != "eligible" && decision != "excluded") || strings.TrimSpace(reason) == "" {
		return fmt.Errorf("eligibility decision and reason required")
	}
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO check_applicability VALUES(?,?,?,?,?,?) ON CONFLICT(cred_id,endpoint_id) DO UPDATE SET decision=excluded.decision,reason=excluded.reason,actor=excluded.actor,recorded_at=excluded.recorded_at`, cred, endpoint, decision, reason, user, s.nowMS()); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, s.nowMS(), user, "check_applicability", nil, &cred, reason, jsonOr(map[string]any{"endpoint_id": endpoint, "decision": decision}))
	})
}

func authIdentityTime(run ingest.RunInfo, now int64) int64 {
	if run.FinishedAt > 0 {
		return run.FinishedAt
	}
	if run.StartedAt > 0 {
		return run.StartedAt
	}
	if run.Kind == "manual" {
		return now
	}
	return 0
}
