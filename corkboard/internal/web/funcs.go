package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"corkboard/internal/accessgraph"
	"corkboard/internal/coverage"
	"corkboard/internal/model"
)

func funcMap() template.FuncMap {
	return template.FuncMap{
		"tsAgo":         tsAgo,
		"stamp":         accessgraph.Stamp,
		"historyLines":  historyLines,
		"list":          func(v ...string) []string { return v },
		"bestHost":      model.BestHostname,
		"isDynamicRPC":  isDynamicRPC,
		"dynamicRPC":    dynamicRPC,
		"serviceOwner":  serviceOwner,
		"exploredCount": exploredCount,
		"tasksFor":      tasksFor,
		"latestLog":     latestLog,
		"logCount":      logCount,
		"deref":         func(p *int64) int64 { return *p },
		"cardit":        cardit,
		"stageName":     stageName,
		"statusName":    func(status string) string { return strings.ReplaceAll(status, "_", " ") },
		"stages":        coverage.Stages,
	}
}

func stageName(stage string) string {
	names := map[string]string{
		"discovery": "Discovery", "tcp_top": "Top TCP ports", "tcp_full": "Full TCP",
		"svc_version": "Service versions", "udp_top": "UDP ports", "nse_default": "Default scripts",
		"nxc_smb": "SMB sweep", "web_shots": "Web screenshots", "vuln_scan": "Vulnerability scan",
	}
	if name, ok := names[stage]; ok {
		return name
	}
	return strings.ReplaceAll(stage, "_", " ")
}

func tsAgo(ms int64) string {
	if ms == 0 {
		return "—"
	}
	d := time.Now().UnixMilli() - ms
	if d < 0 {
		d = 0
	}
	switch {
	case d < 60_000:
		return fmt.Sprintf("%ds", d/1000)
	case d < 3_600_000:
		return fmt.Sprintf("%dm", d/60_000)
	case d < 86_400_000:
		return fmt.Sprintf("%.1fh", float64(d)/3_600_000)
	default:
		return fmt.Sprintf("%dd", d/86_400_000)
	}
}

type cardData struct {
	ID        int64
	Title     string
	Body      string
	Commands  []string
	HostIP    string
	ServiceID *int64
	Service   string
	Priority  int
	State     string
	Owner     string
	UpdatedAt int64
	CSRF      string
	Steal     bool
}

func cardit(t model.Task, csrf string, user string) cardData {
	return cardData{
		ID: t.ID, Title: t.Title, Body: t.Body, HostIP: t.HostIP, ServiceID: t.ServiceID, Service: t.Service,
		Commands: t.Commands,
		Priority: t.Priority, State: t.State, Owner: t.Owner,
		UpdatedAt: t.UpdatedAt, CSRF: csrf,
		Steal: t.Owner != "" && t.Owner != user,
	}
}

func historyLines(detail string) []string {
	var obj map[string]any
	if json.Unmarshal([]byte(detail), &obj) != nil {
		if detail == "" {
			return nil
		}
		return []string{detail}
	}
	show := func(v any) string {
		if s, ok := v.(string); ok {
			return s
		}

		if list, ok := v.([]any); ok {
			refs := make([]string, 0, len(list))
			for _, item := range list {
				m, ok := item.(map[string]any)
				if !ok || m["kind"] == nil || m["id"] == nil {
					refs = nil
					break
				}
				refs = append(refs, fmt.Sprintf("%v:%v", m["kind"], m["id"]))
			}
			if refs != nil {
				return strings.Join(refs, ", ")
			}
		}
		b, _ := json.Marshal(v)
		return string(b)
	}
	empty := func(v any) bool {
		switch x := v.(type) {
		case nil:
			return true
		case string:
			return x == ""
		case float64:
			return x == 0
		case []any:
			return len(x) == 0
		}
		return false
	}
	var out []string
	if change, ok := obj["change"].(map[string]any); ok {
		before, _ := obj["before"].(map[string]any)
		for _, k := range sortedKeys(change) {
			if empty(change[k]) {
				continue
			}
			if old := before[k]; !empty(old) && show(old) != show(change[k]) {
				out = append(out, fmt.Sprintf("%s: %s → %s", k, show(old), show(change[k])))
			} else if show(before[k]) != show(change[k]) {
				out = append(out, fmt.Sprintf("%s: %s", k, show(change[k])))
			}
		}
		return out
	}
	for _, k := range sortedKeys(obj) {
		if !empty(obj[k]) {
			out = append(out, fmt.Sprintf("%s: %s", k, show(obj[k])))
		}
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isDynamicRPC(s model.Service) bool {
	return s.Proto == "tcp" && s.Port >= 49152 && (s.Name == "" || s.Name == "msrpc" || s.Name == "unknown")
}

func dynamicRPC(services []model.Service) []model.Service {
	var out []model.Service
	for _, s := range services {
		if isDynamicRPC(s) {
			out = append(out, s)
		}
	}
	return out
}

func serviceOwner(claims []model.TargetClaim, id int64) string {
	for _, c := range claims {
		if c.Kind == "service" && c.RefID == id {
			return c.Owner
		}
	}
	return ""
}

func exploredCount(services []model.Service) string {
	n, total := 0, 0
	for _, s := range services {
		if isDynamicRPC(s) {
			continue
		}
		total++
		if s.ExploredAt != nil {
			n++
		}
	}
	return fmt.Sprintf("%d of %d", n, total)
}

func tasksFor(tasks []model.Task, id int64) []model.Task {
	var out []model.Task
	for _, t := range tasks {
		if t.ServiceID != nil && *t.ServiceID == id && (t.State == "open" || t.State == "claimed" || t.State == "blocked") {
			out = append(out, t)
		}
	}
	return out
}

func latestLog(notes []model.Note, id int64) *model.Note {
	for i := range notes {
		if notes[i].ServiceID != nil && *notes[i].ServiceID == id {
			return &notes[i]
		}
	}
	return nil
}

func logCount(notes []model.Note, id int64) int {
	n := 0
	for _, e := range notes {
		if e.ServiceID != nil && *e.ServiceID == id {
			n++
		}
	}
	return n
}
