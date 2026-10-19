package store

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type TargetRef struct {
	Kind string `json:"kind"`
	ID   int64  `json:"id"`
}
type Target struct {
	ID        int64  `json:"target_id"`
	Kind      string `json:"kind"`
	RefID     int64  `json:"id"`
	HostID    *int64 `json:"host_id,omitempty"`
	ServiceID *int64 `json:"service_id,omitempty"`
	Label     string `json:"label"`
}

func ParseTarget(v string) (TargetRef, error) {
	p := strings.Split(v, ":")
	if len(p) != 2 {
		return TargetRef{}, fmt.Errorf("target must be host:ID, service:ID, application:ID, or task:ID")
	}
	id, err := strconv.ParseInt(p[1], 10, 64)
	if err != nil || id <= 0 {
		return TargetRef{}, fmt.Errorf("invalid target ID")
	}
	t := TargetRef{p[0], id}
	if targetColumn(t.Kind) == "" {
		return t, fmt.Errorf("invalid target kind")
	}
	return t, nil
}
func targetColumn(kind string) string {
	switch kind {
	case "host":
		return "host_id"
	case "service":
		return "service_id"
	case "application":
		return "application_id"
	case "task":
		return "task_id"
	}
	return ""
}
func targetTx(ctx context.Context, tx *sql.Tx, t TargetRef) (int64, error) {
	col := targetColumn(t.Kind)
	if col == "" || t.ID <= 0 {
		return 0, fmt.Errorf("invalid target")
	}
	if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO work_targets("+col+") VALUES(?)", t.ID); err != nil {
		return 0, fmt.Errorf("unknown %s target: %w", t.Kind, err)
	}
	var id int64
	err := tx.QueryRowContext(ctx, "SELECT id FROM work_targets WHERE "+col+"=?", t.ID).Scan(&id)
	return id, err
}
func (s *Store) ResolveTarget(ctx context.Context, ref TargetRef) (*Target, error) {
	var id int64
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error { var err error; id, err = targetTx(ctx, tx, ref); return err })
	if err != nil {
		return nil, err
	}
	var t Target
	err = s.db.Read.QueryRowContext(ctx, `SELECT id,kind,ref_id,host_id,service_id,label FROM target_details WHERE id=?`, id).Scan(&t.ID, &t.Kind, &t.RefID, &t.HostID, &t.ServiceID, &t.Label)
	return &t, err
}

type Application struct {
	ID        int64  `json:"id"`
	Origin    string `json:"origin"`
	Realm     string `json:"realm"`
	HostID    *int64 `json:"host_id,omitempty"`
	ServiceID *int64 `json:"service_id,omitempty"`
	Retired   bool   `json:"retired"`
}

func (s *Store) AddApplication(ctx context.Context, user string, a Application) (int64, error) {
	u, err := url.Parse(a.Origin)
	if err != nil || u.Hostname() == "" || (strings.ToLower(u.Scheme) != "http" && strings.ToLower(u.Scheme) != "https") || u.User != nil {
		return 0, fmt.Errorf("application requires an http(s) origin")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("invalid origin port")
		}
	}
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	origin := u.Scheme + "://" + host
	if len(a.Realm) > 256 {
		return 0, fmt.Errorf("realm exceeds 256 bytes")
	}
	var id int64
	err = s.db.WithTx(ctx, func(tx *sql.Tx) error {
		if a.ServiceID != nil {
			var hid int64
			if err := tx.QueryRowContext(ctx, "SELECT host_id FROM services WHERE id=?", *a.ServiceID).Scan(&hid); err != nil {
				return err
			}
			if a.HostID != nil && *a.HostID != hid {
				return fmt.Errorf("application service/host mismatch")
			}
			a.HostID = &hid
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO applications(origin,realm,host_id,service_id,created_at) VALUES(?,?,?,?,?) ON CONFLICT(origin,realm) DO NOTHING`, origin, a.Realm, a.HostID, a.ServiceID, s.nowMS())
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if err = tx.QueryRowContext(ctx, "SELECT id FROM applications WHERE origin=? AND realm=?", origin, a.Realm).Scan(&id); err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		if err = s.syncEndpoint(ctx, tx, TargetRef{"application", id}, "web", "", origin+"|"+a.Realm, "open", user, nil, s.nowMS()); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, s.nowMS(), user, "application_new", a.HostID, &id, "application: "+origin, "{}")
	})
	return id, err
}
func (s *Store) Applications(ctx context.Context) ([]Application, error) {
	rows, err := s.db.Read.QueryContext(ctx, "SELECT id,origin,realm,host_id,service_id,retired FROM applications ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Application{}
	for rows.Next() {
		var a Application
		if err = rows.Scan(&a.ID, &a.Origin, &a.Realm, &a.HostID, &a.ServiceID, &a.Retired); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type ApplicationPatch struct {
	Realm   *string `json:"realm"`
	Retired *bool   `json:"retired"`
}

func (s *Store) PatchApplication(ctx context.Context, user string, id int64, in ApplicationPatch) error {
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var origin, realm string
		var retired bool
		if err := tx.QueryRowContext(ctx, "SELECT origin,realm,retired FROM applications WHERE id=?", id).Scan(&origin, &realm, &retired); err != nil {
			return err
		}
		if in.Realm != nil {
			if len(*in.Realm) > 256 {
				return fmt.Errorf("realm exceeds 256 bytes")
			}
			realm = *in.Realm
		}
		if in.Retired != nil {
			retired = *in.Retired
		}
		if _, err := tx.ExecContext(ctx, "UPDATE applications SET realm=?,retired=? WHERE id=?", realm, retired, id); err != nil {
			return err
		}
		state := "open"
		if retired {
			state = "closed"
		}
		if err := s.syncEndpoint(ctx, tx, TargetRef{"application", id}, "web", "", origin+"|"+realm, state, user, nil, s.nowMS()); err != nil {
			return err
		}
		return s.appendEvent(ctx, tx, s.nowMS(), user, "application_changed", nil, &id, "application authentication identity/state updated", jsonOr(in))
	})
}
