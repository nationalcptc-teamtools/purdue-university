package server

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"corkboard/internal/model"
	"corkboard/internal/store"
)

var compromiseLevels = map[string]bool{
	"user": true, "admin": true, "system": true, "domain_admin": true,
}

func (s *Server) handleSetOwned(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	var body struct {
		Level        string `json:"level"`
		ViaFindingID *int64 `json:"via_finding_id"`
		ViaCredID    *int64 `json:"via_cred_id"`
		ViaText      string `json:"via_text"`
	}
	if err := decodeJSON(r, &body); err != nil {
		s.writeDecodeErr(w, err)
		return
	}
	if !compromiseLevels[body.Level] {
		writeErr(w, http.StatusBadRequest, "invalid_request", "level must be user, admin, system, or domain_admin")
		return
	}
	if body.ViaCredID != nil {
		c, err := s.store.GetCred(r.Context(), *body.ViaCredID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "unknown cred id")
			return
		}
		_ = c
	}
	if body.ViaFindingID != nil {
		var n int
		if err := s.store.DB().Read.QueryRowContext(r.Context(),
			`SELECT 1 FROM findings WHERE id = ?`, *body.ViaFindingID).Scan(&n); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "unknown finding id")
			return
		}
	}
	if body.ViaText == "" && body.ViaCredID == nil && body.ViaFindingID == nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "provide via_text, via_cred_id, or via_finding_id")
		return
	}
	if err := s.store.SetCompromise(r.Context(), ip, userFrom(r.Context()), body.Level,
		body.ViaFindingID, body.ViaCredID, body.ViaText); err != nil {
		switch err {
		case store.ErrUnknownHost:
			writeErr(w, http.StatusBadRequest, "invalid_request", "unknown host "+ip)
		default:
			s.credErr(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": ip, "level": body.Level})
}

var exportKinds = map[string]bool{
	"hosts.csv": true, "services.csv": true, "creds.csv": true,
	"findings.csv": true, "all.json": true, "appendix.md": true,
	"narrative.md": true, "bloodhound-owned.txt": true,
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if !exportKinds[kind] {
		writeErr(w, http.StatusBadRequest, "invalid_request",
			"kind must be one of hosts.csv, services.csv, creds.csv, findings.csv, all.json, appendix.md, narrative.md, bloodhound-owned.txt")
		return
	}
	ctx := r.Context()

	switch kind {
	case "bloodhound-owned.txt":
		body, err := s.bh.ExportOwned(ctx)
		if err != nil {
			writeErr(w, 500, "internal_error", "BloodHound export failed")
			return
		}
		writeText(w, body)
	case "hosts.csv":
		hosts, err := s.store.ListExportHosts(ctx)
		if err != nil {
			s.log.Error("export hosts", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal_error", "export failed")
			return
		}
		writeCSV(w, hostsCSV(hosts), "text/csv; charset=utf-8")
	case "services.csv":
		rows, err := s.store.ListServicesCSV(ctx)
		if err != nil {
			s.log.Error("export services", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal_error", "export failed")
			return
		}
		writeCSV(w, servicesCSV(rows), "text/csv; charset=utf-8")
	case "creds.csv":
		creds, err := s.store.ListCreds(ctx)
		if err != nil {
			s.log.Error("export creds", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal_error", "export failed")
			return
		}
		sums, err := s.store.CredAccessSummaries(ctx)
		if err != nil {
			s.log.Error("export creds", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal_error", "export failed")
			return
		}
		byID := map[int64]store.CredAccessSummary{}
		for _, su := range sums {
			byID[su.CredID] = su
		}
		writeCSV(w, credsCSV(creds, byID), "text/csv; charset=utf-8")
	case "findings.csv":
		rows, err := s.store.ListFindingsCSV(ctx)
		if err != nil {
			s.log.Error("export findings", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal_error", "export failed")
			return
		}
		writeCSV(w, findingsCSV(rows), "text/csv; charset=utf-8")
	case "appendix.md":
		hosts, err := s.store.ListExportHosts(ctx)
		if err != nil {
			s.log.Error("export appendix", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal_error", "export failed")
			return
		}
		ports, err := s.store.ListOpenServices(ctx)
		if err != nil {
			s.log.Error("export appendix", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal_error", "export failed")
			return
		}
		writeText(w, appendixMD(s.cfg.EngagementName, hosts, ports))
	case "narrative.md":
		comps, err := s.store.ListCompromises(ctx)
		if err != nil {
			s.log.Error("export narrative", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal_error", "export failed")
			return
		}
		adminEvents, err := s.store.ListEvents(ctx, 0, 500, []string{store.EventCredAccessAdmin}, nil)
		if err != nil {
			s.log.Error("export narrative", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal_error", "export failed")
			return
		}
		creds, err := s.store.ListCreds(ctx)
		if err != nil {
			s.log.Error("export narrative", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal_error", "export failed")
			return
		}
		names := map[string]string{}
		for _, c := range creds {
			names[strconv.FormatInt(c.ID, 10)] = model.CredName(c.Domain, c.Username)
		}
		for i, e := range adminEvents {

			adminEvents[i].Summary = oldCredSummary.ReplaceAllStringFunc(e.Summary, func(m string) string {
				id := oldCredSummary.FindStringSubmatch(m)[1]
				if n, ok := names[id]; ok {
					return "admin access as " + n + " on"
				}
				return m
			})
		}
		writeText(w, narrativeMD(s.cfg.EngagementName, comps, adminEvents))
	case "all.json":
		doc, err := s.allJSON(ctx)
		if err != nil {
			s.log.Error("export all", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal_error", "export failed")
			return
		}
		b, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "export failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}
}

func writeText(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(body))
}

func writeCSV(w http.ResponseWriter, rows [][]string, contentType string) {
	w.Header().Set("Content-Type", contentType)
	cw := csv.NewWriter(w)
	for _, r := range rows {
		cw.Write(r)
	}
	cw.Flush()
}

func hostsCSV(hosts []store.ExportHost) [][]string {
	out := [][]string{{"ip", "hostnames", "os", "domain", "mac", "zone", "status", "owner", "priority", "first_seen", "last_seen"}}
	for _, h := range hosts {
		out = append(out, []string{
			h.IP, strings.Join(h.HostnameList, ","), h.OS, h.Domain, h.MAC,
			h.Zone, h.Status, h.Owner, strconv.Itoa(h.Priority),
			strconv.FormatInt(h.FirstSeen, 10), strconv.FormatInt(h.LastSeen, 10),
		})
	}
	return out
}

func servicesCSV(rows []store.ServiceCSV) [][]string {
	out := [][]string{{"ip", "proto", "port", "state", "name", "product", "version"}}
	for _, r := range rows {
		out = append(out, []string{r.IP, r.Proto, strconv.Itoa(r.Port), r.State, r.Name, r.Product, r.Version})
	}
	return out
}

func credsCSV(creds []model.Cred, sums map[int64]store.CredAccessSummary) [][]string {
	out := [][]string{{"id", "user", "secret", "secret_type", "source", "added_by", "valid_on", "admin_on"}}
	for _, c := range creds {
		secret := c.Secret
		user := c.Username
		if c.Domain != "" {
			user = c.Domain + `\` + c.Username
		}
		su := sums[c.ID]
		out = append(out, []string{
			strconv.FormatInt(c.ID, 10), user, secret, c.SecretType, c.Source,
			c.AddedBy, strings.Join(su.ValidOn, ","), strings.Join(su.AdminOn, ","),
		})
	}
	return out
}

func findingsCSV(rows []store.FindingCSV) [][]string {
	out := [][]string{{"id", "title", "severity", "source", "state", "hosts"}}
	for _, r := range rows {
		out = append(out, []string{
			strconv.FormatInt(r.ID, 10), r.Title, r.Severity, r.Source, r.State, r.Hosts,
		})
	}
	return out
}

var oldCredSummary = regexp.MustCompile(`^admin access for cred (\d+) on`)

func narrativeMD(engagement string, comps []store.CompromiseRow, adminEvents []model.Event) string {
	type entry struct {
		at    int64
		actor string
		line  string
	}
	var entries []entry
	for _, c := range comps {
		entries = append(entries, entry{c.At, c.ByUser, lineForCompromise(c)})
	}
	for _, e := range adminEvents {
		entries = append(entries, entry{e.At, e.Actor, e.Summary})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].at < entries[j].at })

	var b strings.Builder
	fmt.Fprintf(&b, "# Attack Narrative — %s\n\n", engagement)
	b.WriteString("Chronological compromises and admin credential discoveries.\n")
	b.WriteString("Generated from the corkboard event log.\n\n")
	if len(entries) == 0 {
		b.WriteString("_No compromises recorded yet._\n")
		return b.String()
	}
	b.WriteString("| Time (UTC) | Actor | What happened |\n")
	b.WriteString("|---|---|---|\n")
	for _, e := range entries {
		ts := time.UnixMilli(e.at).UTC().Format("15:04:05")
		fmt.Fprintf(&b, "| %s | %s | %s |\n", ts, e.actor, e.line)
	}
	return b.String()
}

func lineForCompromise(c store.CompromiseRow) string {
	via := []string{}
	if c.ViaFindingID != nil && c.FindingTitle != "" {
		via = append(via, "finding "+strconv.FormatInt(*c.ViaFindingID, 10)+" ("+c.FindingTitle+")")
	}
	if c.CredUser != "" {
		via = append(via, "credential "+c.CredUser)
	}
	if c.ViaText != "" {
		via = append(via, c.ViaText)
	}
	return fmt.Sprintf("%s compromised **%s** — %s", c.IP, c.Level, strings.Join(via, "; "))
}

func appendixMD(engagement string, hosts []store.ExportHost, ports []store.OpenPortSummary) string {
	portsByIP := map[string][]store.OpenPortSummary{}
	for _, p := range ports {
		portsByIP[p.IP] = append(portsByIP[p.IP], p)
	}
	var subnets []*subnetGroup
	byKey := map[string]*subnetGroup{}
	for _, h := range hosts {
		if h.Zone == "out" {
			continue
		}
		k := store.SubnetKey(h.IP)
		su, ok := byKey[k]
		if !ok {
			su = &subnetGroup{key: k}
			byKey[k] = su
			subnets = append(subnets, su)
		}
		su.hosts = append(su.hosts, h)
	}

	sort.SliceStable(subnets, func(i, j int) bool {
		return subnetSortKey(*subnets[i]) < subnetSortKey(*subnets[j])
	})

	var b strings.Builder
	fmt.Fprintf(&b, "# Appendix — Scanned Systems: %s\n\n", engagement)
	b.WriteString("_Generated from the corkboard. In-scope hosts grouped by subnet._\n\n")
	for _, su := range subnets {
		fmt.Fprintf(&b, "## %s\n\n", su.key)
		b.WriteString("| IP | Hostname | OS | Open ports | Compromised |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, h := range su.hosts {
			var portList []string
			dynamicRPC := 0
			for _, p := range portsByIP[h.IP] {

				if p.Proto == "tcp" && p.Port >= 49152 && (p.Name == "" || p.Name == "msrpc" || p.Name == "unknown") {
					dynamicRPC++
					continue
				}
				if p.Name != "" {
					portList = append(portList, fmt.Sprintf("%d/%s/%s", p.Port, p.Proto, p.Name))
				} else {
					portList = append(portList, fmt.Sprintf("%d/%s", p.Port, p.Proto))
				}
			}
			if dynamicRPC > 0 {
				portList = append(portList, fmt.Sprintf("%d dynamic RPC ports (49152+)", dynamicRPC))
			}
			comp := "no"
			if h.Status == "compromised" {
				comp = "**yes**"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				h.IP,
				strings.Join(h.HostnameList, ", "),
				mdCell(h.OS),
				strings.Join(portList, ", "),
				comp)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func mdCell(s string) string {
	if s == "" {
		return ""
	}
	return strings.ReplaceAll(s, "|", "\\|")
}

type subnetGroup struct {
	key   string
	hosts []store.ExportHost
}

func subnetSortKey(su subnetGroup) string {
	if len(su.hosts) == 0 {
		return su.key
	}
	return su.hosts[0].IP
}

func (s *Server) allJSON(ctx context.Context) (map[string]any, error) {
	doc, err := s.store.DumpAll(ctx)
	if err != nil {
		return nil, err
	}
	doc["version"] = 1
	doc["engagement"] = s.cfg.EngagementName
	doc["generated"] = time.Now().UTC().Format(time.RFC3339)
	return doc, nil
}
