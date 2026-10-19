package ingest

import (
	"fmt"
	"strconv"
	"strings"
)

const BatchVersion = 1

const ScriptOutputLimit = 16 * 1024

const MaxNoteBytes = 8 * 1024

const MaxEvidenceBytes = 2 * 1024

type Batch struct {
	Version    int           `json:"version"`
	Run        RunInfo       `json:"run"`
	Hosts      []HostObs     `json:"hosts"`
	WebResults []WebObs      `json:"web_results,omitempty"`
	Creds      []CredObs     `json:"creds,omitempty"`
	Access     []AccessObs   `json:"access,omitempty"`
	Shares     []ShareObs    `json:"shares,omitempty"`
	Vulns      []VulnObs     `json:"vulns,omitempty"`
	Coverage   []CoverageObs `json:"coverage,omitempty"`
	Warnings   []string      `json:"warnings,omitempty"`
}

type RunInfo struct {
	Fidelity   int        `json:"fidelity,omitempty"`
	Vantage    string     `json:"vantage,omitempty"`
	Exit       string     `json:"exit,omitempty"`
	Error      string     `json:"error,omitempty"`
	Kind       string     `json:"kind"`
	Protocol   string     `json:"protocol,omitempty"`
	Command    string     `json:"command,omitempty"`
	SourceName string     `json:"source_name,omitempty"`
	SourceSHA  string     `json:"source_sha256,omitempty"`
	StartedAt  int64      `json:"started_at,omitempty"`
	FinishedAt int64      `json:"finished_at,omitempty"`
	ScanInfo   []ScanInfo `json:"scaninfo,omitempty"`
}

type ScanInfo struct {
	Protocol    string `json:"protocol"`
	Services    string `json:"services"`
	NumServices int    `json:"numservices"`
}

type HostObs struct {
	Scan        *ScanEvidence     `json:"scan,omitempty"`
	OSEvidence  []OSEvidence      `json:"os_evidence,omitempty"`
	IP          string            `json:"ip"`
	Hostnames   []NameObs         `json:"hostnames,omitempty"`
	OS          string            `json:"os,omitempty"`
	OSAcc       int               `json:"os_accuracy,omitempty"`
	Domain      string            `json:"domain,omitempty"`
	MAC         string            `json:"mac,omitempty"`
	MACVendor   string            `json:"mac_vendor,omitempty"`
	Attrs       map[string]string `json:"attrs,omitempty"`
	Services    []ServiceObs      `json:"services,omitempty"`
	HostScripts []ScriptObs       `json:"host_scripts,omitempty"`
}

type NameObs struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

type ServiceObs struct {
	Method     string      `json:"method,omitempty"`
	Confidence int         `json:"confidence,omitempty"`
	OSHint     string      `json:"os_hint,omitempty"`
	Proto      string      `json:"proto"`
	Port       int         `json:"port"`
	State      string      `json:"state,omitempty"`
	Name       string      `json:"name,omitempty"`
	Product    string      `json:"product,omitempty"`
	Version    string      `json:"version,omitempty"`
	ExtraInfo  string      `json:"extrainfo,omitempty"`
	Tunnel     string      `json:"tunnel,omitempty"`
	CPE        []string    `json:"cpe,omitempty"`
	Scripts    []ScriptObs `json:"scripts,omitempty"`
}

type ScriptObs struct {
	ID     string `json:"id"`
	Output string `json:"output"`
}

type CredObs struct {
	Ref        string `json:"ref"`
	Domain     string `json:"domain,omitempty"`
	Username   string `json:"username"`
	Secret     string `json:"secret"`
	SecretType string `json:"secret_type"`
	Source     string `json:"source,omitempty"`
}

type AccessObs struct {
	ObservedAt int64  `json:"observed_at,omitempty"`
	CredRef    string `json:"cred_ref"`
	IP         string `json:"ip"`
	Protocol   string `json:"protocol"`
	Level      string `json:"level"`
}

type ShareObs struct {
	IP      string `json:"ip"`
	Name    string `json:"name"`
	Remark  string `json:"remark,omitempty"`
	CredRef string `json:"cred_ref,omitempty"`
	Read    bool   `json:"read"`
	Write   bool   `json:"write"`
}

type WebObs struct {
	URL           string   `json:"url"`
	FinalURL      string   `json:"final_url,omitempty"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title,omitempty"`
	Technologies  []string `json:"technologies,omitempty"`
	TLSSubject    string   `json:"tls_subject,omitempty"`
	TLSSANs       []string `json:"tls_sans,omitempty"`
	ScreenshotSHA string   `json:"screenshot_sha,omitempty"`
	Failed        bool     `json:"failed"`
	FailedReason  string   `json:"failed_reason,omitempty"`
	ProbedAt      int64    `json:"probed_at,omitempty"`
}

type VulnObs struct {
	TemplateID  string   `json:"template_id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	References  []string `json:"references,omitempty"`
	CVE         string   `json:"cve,omitempty"`
	IP          string   `json:"ip"`
	Port        int      `json:"port"`
	MatchedAt   string   `json:"matched_at,omitempty"`
	Extracted   string   `json:"extracted,omitempty"`
}

func TruncateScriptOutput(s string) string {
	if len(s) <= ScriptOutputLimit {
		return s
	}
	return s[:ScriptOutputLimit] + "…[truncated]"
}

type CoverageObs struct {
	IP    string `json:"ip"`
	Stage string `json:"stage"`
}

type Result struct {
	RunID        int64    `json:"run_id"`
	Duplicate    bool     `json:"duplicate,omitempty"`
	NewHosts     int      `json:"new_hosts"`
	UpdatedHosts int      `json:"updated_hosts"`
	NewServices  int      `json:"new_services"`
	NewCreds     int      `json:"new_creds"`
	OutOfScope   []string `json:"out_of_scope,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`

	touched []int64
}

func (r Result) TouchedHostIDs() []int64 { return r.touched }

func (r *Result) SetTouched(ids []int64) { r.touched = ids }

func ParsePortList(s string) (map[int]bool, error) {
	out := make(map[int]bool)
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return out, nil
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err := strconv.Atoi(strings.TrimSpace(lo))
			if err != nil {
				return nil, fmt.Errorf("port range %q: %w", part, err)
			}
			b, err := strconv.Atoi(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("port range %q: %w", part, err)
			}
			if a > b {
				a, b = b, a
			}
			if a < 0 || b > 65535 {
				return nil, fmt.Errorf("port range %q out of range", part)
			}
			for p := a; p <= b; p++ {
				out[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("port %q: %w", part, err)
			}
			out[p] = true
		}
	}
	for p := range out {
		if p < 0 || p > 65535 {
			return nil, fmt.Errorf("port %d out of range", p)
		}
	}
	return out, nil
}
