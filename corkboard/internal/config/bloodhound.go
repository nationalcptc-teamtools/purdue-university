package config

import (
	"fmt"
	"net/url"
	"regexp"

	"gopkg.in/yaml.v3"
)

type BloodHound struct {
	Enabled     bool   `yaml:"enabled"`
	URL         string `yaml:"url"`
	TokenIDEnv  string `yaml:"token_id_env"`
	TokenKeyEnv string `yaml:"token_key_env"`
	AutoSync    bool   `yaml:"auto_sync"`
}

func (b *BloodHound) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("bloodhound: must be a mapping")
	}
	allowed := map[string]bool{"enabled": true, "url": true, "token_id_env": true, "token_key_env": true, "auto_sync": true}
	for i := 0; i < len(node.Content); i += 2 {
		if !allowed[node.Content[i].Value] {
			return fmt.Errorf("bloodhound: unknown field %q (credentials must use token_id_env and token_key_env)", node.Content[i].Value)
		}
	}
	type plain BloodHound
	return node.Decode((*plain)(b))
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (b BloodHound) Validate() error {
	if !b.Enabled {
		return nil
	}
	u, err := url.Parse(b.URL)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("bloodhound.url: enabled integration requires an absolute http(s) URL without credentials, query, or fragment")
	}
	if !envName.MatchString(b.TokenIDEnv) || !envName.MatchString(b.TokenKeyEnv) {
		return fmt.Errorf("bloodhound: token_id_env and token_key_env must name environment variables (e.g. BH_TOKEN_ID and BH_TOKEN_KEY)")
	}
	return nil
}
