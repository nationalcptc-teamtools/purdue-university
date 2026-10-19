package coverage

import (
	"strings"

	"corkboard/internal/ingest"
)

const (
	StageDiscovery  = "discovery"
	StageTCPTop     = "tcp_top"
	StageTCPFull    = "tcp_full"
	StageSvcVersion = "svc_version"
	StageUDPTop     = "udp_top"
	StageNSEDefault = "nse_default"
	StageNXCSMB     = "nxc_smb"
	StageWebShots   = "web_shots"
	StageVulnScan   = "vuln_scan"
)

func Stages() []string {
	return []string{
		StageDiscovery, StageTCPTop, StageTCPFull, StageSvcVersion,
		StageUDPTop, StageNSEDefault, StageNXCSMB, StageWebShots, StageVulnScan,
	}
}

func StagesForRun(run ingest.RunInfo) []string {
	set := map[string]bool{StageDiscovery: true}
	switch run.Kind {
	case "nmap", "masscan":
		for _, s := range scanStages(run) {
			set[s] = true
		}
	case "nxc":
		if run.Protocol == "smb" {
			set[StageNXCSMB] = true
		}
	case "nuclei":
		set[StageVulnScan] = true
	case "gowitness", "manual":

	}
	return filterByOrder(set)
}

func UniformStages(run ingest.RunInfo) []string {
	var out []string
	for _, s := range StagesForRun(run) {
		if s != StageVulnScan {
			out = append(out, s)
		}
	}
	return out
}

func scanStages(run ingest.RunInfo) []string {
	var out []string
	top := false
	full := false
	for _, si := range run.ScanInfo {
		switch si.Protocol {
		case "tcp":
			switch {
			case si.NumServices >= 65535:
				ports, err := ingest.ParsePortList(si.Services)
				if err == nil && len(ports) >= 65535 {
					full = true
					for p := 1; p <= 65535; p++ {
						if !ports[p] {
							full = false
							break
						}
					}
				}
			case si.NumServices >= 100 && si.NumServices <= 10000:
				top = true
			}
		case "udp":
			if run.Kind == "nmap" {
				out = append(out, StageUDPTop)
			}
		}
	}
	args := run.Command
	if full || (len(run.ScanInfo) == 0 && isFullTCPScan(args)) {
		out = append(out, StageTCPFull)
	} else if top {
		out = append(out, StageTCPTop)
	}

	if run.Kind == "nmap" {
		if hasFlag(args, "-sV") || hasFlag(args, "-A") {
			out = append(out, StageSvcVersion)
		}
		if defaultScripts(args) {
			out = append(out, StageNSEDefault)
		}
	}
	return out
}

func defaultScripts(args string) bool {
	fields := strings.Fields(args)
	explicit := false
	selected := false
	for i, t := range fields {
		value := ""
		if t == "--script" && i+1 < len(fields) {
			value = fields[i+1]
			explicit = true
		}
		if strings.HasPrefix(t, "--script=") {
			value = strings.TrimPrefix(t, "--script=")
			explicit = true
		}
		for _, part := range strings.Split(value, ",") {
			if part == "default" {
				selected = true
			}
		}
	}
	if explicit {
		return selected
	}
	return hasFlag(args, "-sC") || hasFlag(args, "-A")
}

func HostStageStatus(run ingest.RunInfo, h ingest.HostObs, stage string) string {
	if run.Kind != "nmap" && run.Kind != "masscan" {
		return "completed"
	}
	if h.Scan == nil || run.Fidelity == 0 {
		if stage == StageDiscovery {
			for _, svc := range h.Services {
				if svc.State == "" || svc.State == "open" {
					return "completed"
				}
			}
		}
		return "attempted"
	}
	if stage == StageDiscovery {
		if h.Scan.Responded {
			return "completed"
		}
		return "attempted"
	}
	if run.Exit != "success" || h.Scan.TimedOut {
		return "partial"
	}
	if stage == StageTCPTop {
		count := 0
		for _, si := range run.ScanInfo {
			if si.Protocol == "tcp" {
				count += si.NumServices
			}
		}
		if count < 1000 {
			return "partial"
		}
	}
	if stage == StageUDPTop {
		count := 0
		for _, si := range run.ScanInfo {
			if si.Protocol == "udp" {
				count += si.NumServices
			}
		}
		if count < 100 {
			return "partial"
		}
	}
	if stage == StageSvcVersion || stage == StageNSEDefault {
		for _, sc := range h.HostScripts {
			if strings.Contains(strings.ToLower(sc.Output), "script execution failed") || strings.Contains(strings.ToLower(sc.Output), "timed out") {
				return "partial"
			}
		}
		if len(h.Services) == 0 {
			return "not_applicable"
		}
		for _, s := range h.Services {
			if stage == StageSvcVersion && s.Method != "probed" {
				return "partial"
			}
			for _, sc := range s.Scripts {
				if strings.Contains(strings.ToLower(sc.Output), "script execution failed") || strings.Contains(strings.ToLower(sc.Output), "timed out") {
					return "partial"
				}
			}
		}

		broad := false
		for _, si := range run.ScanInfo {
			if si.NumServices >= 1000 {
				broad = true
			}
		}
		if !broad {
			return "partial"
		}
	}
	return "completed"
}

func filterByOrder(set map[string]bool) []string {
	var out []string
	for _, s := range Stages() {
		if set[s] {
			out = append(out, s)
		}
	}
	return out
}

func hasFlag(args, flag string) bool {
	for _, tok := range strings.Fields(args) {
		if tok == flag {
			return true
		}
	}
	return false
}

func isFullTCPScan(args string) bool {
	toks := strings.Fields(args)
	for i, tok := range toks {
		switch tok {
		case "-p-", "-p1-65535":
			return true
		case "-p":
			if i+1 < len(toks) && toks[i+1] == "1-65535" {
				return true
			}
		}
	}
	return false
}
