package ingest

import "strings"

type ScanEvidence struct {
	Reason    string       `json:"reason,omitempty"`
	Responded bool         `json:"responded"`
	TimedOut  bool         `json:"timed_out,omitempty"`
	At        int64        `json:"at,omitempty"`
	Ports     []PortState  `json:"ports,omitempty"`
	Extra     []ExtraPorts `json:"extra,omitempty"`
}

type PortState struct {
	Proto  string `json:"proto"`
	Port   int    `json:"port"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type ExtraPorts struct {
	State string `json:"state"`
	Count int    `json:"count"`
	Proto string `json:"proto,omitempty"`
	Ports string `json:"ports,omitempty"`
}

type OSEvidence struct {
	Name     string `json:"name"`
	Family   string `json:"family,omitempty"`
	Build    string `json:"build,omitempty"`
	Source   string `json:"source"`
	Accuracy int    `json:"accuracy,omitempty"`
	At       int64  `json:"at,omitempty"`
}

func OSFamily(name string) string {
	s := strings.ToLower(name)
	for _, f := range []string{"windows", "linux", "freebsd", "openbsd", "netbsd", "android", "ios"} {
		if strings.Contains(s, f) {
			return f
		}
	}
	if strings.Contains(s, "mac os") || strings.Contains(s, "macos") || strings.Contains(s, "darwin") {
		return "macos"
	}
	return "unknown"
}

func (o OSEvidence) Rank() int {
	switch o.Source {
	case "smb-os-discovery", "nxc", "rdp-ntlm-info":
		return 3
	case "nmap-os":
		return 2
	default:
		return 1
	}
}

func (r RunInfo) ObservedAt(fallback int64) int64 {
	if r.FinishedAt > 0 {
		return r.FinishedAt
	}
	if r.StartedAt > 0 {
		return r.StartedAt
	}
	return fallback
}
