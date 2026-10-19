package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Client struct {
	Server         string `yaml:"server"`
	Passphrase     string `yaml:"passphrase"`
	User           string `yaml:"user"`
	TLSFingerprint string `yaml:"tls_fingerprint,omitempty"`
}

func ClientConfigPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("client config path: %w", err)
	}
	return filepath.Join(base, "cork", "client.yaml"), nil
}

func LoadClient() (*Client, error) {
	path, err := ClientConfigPath()
	if err != nil {
		return nil, err
	}
	var c Client
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	} else if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if v := os.Getenv("CORK_SERVER"); v != "" {
		c.Server = v
	}
	if v := os.Getenv("CORK_PASSPHRASE"); v != "" {
		c.Passphrase = v
	}
	if v := os.Getenv("CORK_USER"); v != "" {
		c.User = v
	}
	return &c, nil
}

func (c *Client) Save() error {
	path, err := ClientConfigPath()
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
