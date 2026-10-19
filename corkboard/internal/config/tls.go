package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type TLS struct {
	Mode string `yaml:"-"`
	Cert string `yaml:"cert,omitempty"`
	Key  string `yaml:"key,omitempty"`
}

func (t *TLS) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return err
		}
		switch s {
		case "auto", "off":
			t.Mode = s
		default:
			return fmt.Errorf("tls: must be auto, off, or {cert: ..., key: ...}; got %q", s)
		}
	case yaml.MappingNode:
		var m struct {
			Cert string `yaml:"cert"`
			Key  string `yaml:"key"`
		}
		if err := node.Decode(&m); err != nil {
			return err
		}
		t.Mode, t.Cert, t.Key = "cert", m.Cert, m.Key
	default:
		return fmt.Errorf("tls: expected a string or a {cert, key} mapping")
	}
	return nil
}

func (t TLS) MarshalYAML() (any, error) {
	if t.Mode == "cert" {
		return map[string]string{"cert": t.Cert, "key": t.Key}, nil
	}
	return t.Mode, nil
}
