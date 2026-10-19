package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"corkboard/internal/auth"

	"gopkg.in/yaml.v3"
)

type Webhook struct {
	Name   string   `yaml:"name"`
	URL    string   `yaml:"url"`
	Format string   `yaml:"format"`
	Kinds  []string `yaml:"kinds"`
}

type Ghostwriter struct {
	URL       string `yaml:"url"`
	TokenEnv  string `yaml:"token_env"`
	ProjectID int    `yaml:"project_id"`
	ReportID  int    `yaml:"report_id"`
}

type Server struct {
	Listen          string      `yaml:"listen"`
	TLS             TLS         `yaml:"tls"`
	PassphraseHash  string      `yaml:"passphrase_hash"`
	TeamTokenSHA256 string      `yaml:"team_token_sha256,omitempty"`
	SessionSecret   string      `yaml:"session_secret"`
	EngagementName  string      `yaml:"engagement_name"`
	MaxUploadMB     int         `yaml:"max_upload_mb"`
	BackupEvery     Duration    `yaml:"backup_every"`
	Webhooks        []Webhook   `yaml:"webhooks"`
	Ghostwriter     Ghostwriter `yaml:"ghostwriter"`
	BloodHound      BloodHound  `yaml:"bloodhound"`
}

func DefaultServer(engagement string) *Server {
	return &Server{
		Listen:         "127.0.0.1:8443",
		TLS:            TLS{Mode: "auto"},
		EngagementName: engagement,
		MaxUploadMB:    64,
		BackupEvery:    Duration(15 * time.Minute),
	}
}

func LoadServer(path string) (*Server, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Server
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

func (s *Server) Validate() error {
	var errs []string
	if s.Listen == "" {
		errs = append(errs, "listen: required (e.g. 127.0.0.1:8443)")
	} else if _, _, err := net.SplitHostPort(s.Listen); err != nil {
		errs = append(errs, fmt.Sprintf("listen: %q is not a valid host:port", s.Listen))
	}
	switch s.TLS.Mode {
	case "auto", "off":
	case "cert":
		if s.TLS.Cert == "" || s.TLS.Key == "" {
			errs = append(errs, "tls: cert mode requires both cert and key")
		}
	default:
		errs = append(errs, "tls: must be auto, off, or {cert: ..., key: ...}")
	}
	if s.PassphraseHash == "" && s.TeamTokenSHA256 != "" {
		errs = append(errs, "passphrase_hash: missing; team tokens were replaced by a team passphrase, set one with `cork passphrase --data DIR`")
	} else if _, err := auth.NewVerifier(s.PassphraseHash); err != nil {
		errs = append(errs, "passphrase_hash: "+err.Error()+"; set one with `cork passphrase --data DIR`")
	}
	if dec, err := base64.StdEncoding.DecodeString(s.SessionSecret); err != nil || len(dec) != 32 {
		errs = append(errs, "session_secret: must be base64 of 32 random bytes")
	}
	if s.EngagementName == "" {
		errs = append(errs, "engagement_name: required")
	}
	if s.MaxUploadMB < 1 || s.MaxUploadMB > 4096 {
		errs = append(errs, "max_upload_mb: must be between 1 and 4096")
	}
	if s.BackupEvery.AsDuration() < 0 {
		errs = append(errs, "backup_every: must be >= 0 (0 disables backups)")
	}
	for i, wh := range s.Webhooks {
		if wh.Name == "" || wh.URL == "" {
			errs = append(errs, fmt.Sprintf("webhooks[%d]: name and url are required", i))
			continue
		}
		if wh.Format != "" && wh.Format != "slack" && wh.Format != "json" {
			errs = append(errs, fmt.Sprintf("webhooks[%d]: format must be slack or json", i))
		}
	}
	if err := s.BloodHound.Validate(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid server config:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

func (s *Server) Save(path string) error {
	data, err := yaml.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func GenerateSessionSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate session secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

func SetPassphraseHash(path, hash string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: top level is not a mapping", path)
	}
	m := doc.Content[0]
	var kept []*yaml.Node
	set := false
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		if k.Value == "passphrase_hash" || k.Value == "team_token_sha256" {
			if set {
				continue
			}

			k.Value = "passphrase_hash"
			v.Kind, v.Tag, v.Style, v.Value = yaml.ScalarNode, "!!str", yaml.DoubleQuotedStyle, hash
			set = true
		}
		kept = append(kept, k, v)
	}
	if !set {
		kept = append(kept,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "passphrase_hash"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Style: yaml.DoubleQuotedStyle, Value: hash})
	}
	m.Content = kept
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
