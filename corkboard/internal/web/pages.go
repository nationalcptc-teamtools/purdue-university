package web

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"corkboard/internal/model"
	"corkboard/internal/store"
)

type dashData struct {
	baseData
	Stats       store.DashStats
	Alarms      []model.Event
	UnclaimedP1 []model.Task
	MyClaims    []model.Host
	MyTasks     []model.Task
	Feed        []model.Event
	NewEvents   []model.Event
}

func (w *Web) handleDashboard(wr http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(wr, r)
		return
	}
	ctx := r.Context()
	user := w.User(r)
	d := dashData{baseData: w.pageData(r, "dashboard")}

	st, err := w.st.DashStats(ctx)
	if err != nil {
		http.Error(wr, err.Error(), 500)
		return
	}
	d.Stats = st

	ack := int64(0)
	if v, err := w.st.GetMeta(ctx, "scope_alarm_ack"); err == nil {
		ack, _ = strconv.ParseInt(v, 10, 64)
	}
	d.Alarms, _ = w.st.ListEvents(ctx, ack, 20, []string{store.EventScopeAlarm}, nil)

	p1, _ := w.st.ListTasks(ctx, store.TaskFilter{State: "open", HideLocked: true})
	for _, t := range p1 {
		if t.Priority <= 1 {
			d.UnclaimedP1 = append(d.UnclaimedP1, t)
		}
	}
	if len(d.UnclaimedP1) > 12 {
		d.UnclaimedP1 = d.UnclaimedP1[:12]
	}

	d.MyClaims, _ = w.st.ListHosts(ctx, store.HostFilter{Owner: user, Limit: 20})
	d.MyTasks, _ = w.st.ListTasks(ctx, store.TaskFilter{Owner: user, State: "claimed", HideLocked: true})
	d.Feed, _ = w.st.ListEvents(ctx, 0, 30, nil, nil)
	if d.LastSeenID >= 0 {
		d.NewEvents, _ = w.st.EventsAfter(ctx, d.LastSeenID, 10)
	}

	if max, err := w.st.MaxEventID(ctx); err == nil && max > d.LastSeenID {
		setCookie(wr, lastSeenCookie, strconv.FormatInt(max, 10), 30*24*3600, false)
	}

	if err := w.render(wr, r, "dashboard", d); err != nil {
		w.log.Error("render dashboard", "err", err)
	}
}

type hostsData struct {
	baseData
	Hosts    []hostRow
	F        store.HostFilter
	Total    int
	Statuses []string
}

func (w *Web) handleHosts(wr http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	f := store.HostFilter{
		Q: q.Get("q"), Tag: q.Get("tag"), Status: q.Get("status"),
		Zone: q.Get("zone"), Owner: q.Get("owner"), Sort: q.Get("sort"),
		Service: q.Get("service"),
		HasCred: q.Get("has_cred") == "true" || q.Get("has_cred") == "1", Limit: 5000,
	}
	if f.Sort != "priority" && f.Sort != "last_seen" {
		f.Sort = "ip"
	}
	if p, err := strconv.Atoi(q.Get("port")); err == nil && p > 0 {
		f.Port = p
	}
	if f.Zone != "" {
		f.IncludeOut = f.Zone == "out"
	}
	if f.Q != "" {
		f.IncludeOut = true
	}
	hosts, err := w.st.ListHosts(ctx, f)
	if err != nil {
		http.Error(wr, err.Error(), 500)
		return
	}

	d := hostsData{baseData: w.pageData(r, "hosts")}
	d.F, d.Total, d.Statuses = f, len(hosts),
		[]string{"untouched", "in_progress", "done", "compromised", "locked"}

	if len(hosts) > 0 {
		ids := make([]any, len(hosts))
		for i, h := range hosts {
			ids[i] = h.ID
		}
		groups := map[int64][]svcGroup{}
		rpc := map[int64]int{}
		rows, err := w.st.DB().Read.QueryContext(ctx,
			`SELECT host_id, port, proto, IFNULL(name, ''), IFNULL(tunnel, '') FROM services
			 WHERE host_id IN (`+inPlaceholders(len(ids))+`) AND state = 'open'
			 ORDER BY host_id, port, proto`, ids...)
		if err == nil {
			for rows.Next() {
				var sv model.Service
				if rows.Scan(&sv.HostID, &sv.Port, &sv.Proto, &sv.Name, &sv.Tunnel) != nil {
					continue
				}
				if isDynamicRPC(sv) {
					rpc[sv.HostID]++
					continue
				}
				port := strconv.Itoa(sv.Port)
				if sv.Proto != "tcp" {
					port += "/" + sv.Proto
				}
				typ := model.ServiceType(sv)
				list := groups[sv.HostID]
				found := false
				for i := range list {
					if list[i].Type == typ {
						list[i].Ports = append(list[i].Ports, port)
						found = true
						break
					}
				}
				if !found {
					list = append(list, svcGroup{Type: typ, Ports: []string{port}})
				}
				groups[sv.HostID] = list
			}
			rows.Close()
		}
		hrows := make([]hostRow, 0, len(hosts))
		for _, h := range hosts {
			hrows = append(hrows, hostRow{Host: h, Groups: groups[h.ID], DynamicRPC: rpc[h.ID]})
		}
		d.Hosts = hrows
	}

	if err := w.render(wr, r, "hosts", d); err != nil {
		w.log.Error("render hosts", "err", err)
	}
}

type hostRow struct {
	model.Host
	Groups     []svcGroup
	DynamicRPC int
}

type svcGroup struct {
	Type  string
	Ports []string
}

func inPlaceholders(n int) string {
	return strings.Repeat("?,", n-1) + "?"
}

type hostData struct {
	baseData
	D          *model.HostDetail
	Tasks      []model.Task
	Findings   []model.Finding
	Events     []model.Event
	Compromise *model.Compromise
	Notice     string
	LogService int64
}

func (w *Web) handleHost(wr http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := r.PathValue("ip")
	det, err := w.st.GetHost(ctx, ip)
	if err != nil {
		http.Error(wr, "unknown host", 404)
		return
	}
	d := hostData{baseData: w.pageData(r, "hosts")}
	d.Notice = noticeFrom(r)
	d.Err = formErrorFrom(r)
	d.D = det
	d.Tasks, _ = w.st.ListTasks(ctx, store.TaskFilter{HostID: &det.Host.ID})
	d.Findings, _ = w.st.ListFindings(ctx, store.FindingFilter{})

	f2 := d.Findings[:0]
	for _, f := range d.Findings {
		for _, fh := range f.Hosts {
			if fh.HostID == det.Host.ID {
				f2 = append(f2, f)
				break
			}
		}
	}
	d.Findings = f2
	d.Events, _ = w.st.ListEvents(ctx, 0, 50, nil, &det.Host.ID)
	d.LogService, _ = strconv.ParseInt(r.URL.Query().Get("log"), 10, 64)
	if len(det.Compromises) > 0 {
		c := det.Compromises[len(det.Compromises)-1]
		d.Compromise = &c
	}
	if err := w.render(wr, r, "host", d); err != nil {
		w.log.Error("render host", "err", err)
	}
}

type tasksData struct {
	baseData
	F           tasksFilter
	Open        []model.Task
	Claimed     []model.Task
	Blocked     []model.Task
	Closed      []model.Task
	Notice      string
	NewTask     taskForm
	NewTaskOpen bool
	HostIPs     []string
}

type tasksFilter struct {
	Mine    bool
	PrioMax string
	HostTag string
}

func (w *Web) handleTasks(wr http.ResponseWriter, r *http.Request) {
	w.renderTasks(wr, r, http.StatusOK, taskForm{Priority: "3"}, "")
}

func (w *Web) renderTasks(wr http.ResponseWriter, r *http.Request, code int, form taskForm, formErr string) {
	ctx := r.Context()
	user := w.User(r)
	q := r.URL.Query()
	f := tasksFilter{
		Mine:    q.Get("mine") == "true" || q.Get("mine") == "on",
		PrioMax: q.Get("prio"),
		HostTag: q.Get("hosttag"),
	}
	owner := ""
	if f.Mine {
		owner = user
	}
	prioMax := 99
	if f.PrioMax != "" {
		if n, err := strconv.Atoi(f.PrioMax); err == nil {
			prioMax = n
		}
	}

	var tagHosts map[int64]bool
	if f.HostTag != "" {
		tagHosts = map[int64]bool{}
		hosts, err := w.st.ListHosts(ctx, store.HostFilter{Tag: f.HostTag, Limit: 500})
		if err == nil {
			for _, h := range hosts {
				tagHosts[h.ID] = true
			}
		}
	}

	pick := func(state string, limit int) []model.Task {
		list, err := w.st.ListTasks(ctx, store.TaskFilter{State: state, Owner: owner, HideLocked: true})
		if err != nil {
			return nil
		}
		out := list[:0]
		for _, t := range list {
			if t.Priority > prioMax {
				continue
			}
			if tagHosts != nil && (t.HostID == nil || !tagHosts[*t.HostID]) {
				continue
			}
			out = append(out, t)
		}
		if len(out) > limit {
			out = out[:limit]
		}
		return out
	}

	d := tasksData{baseData: w.pageData(r, "tasks")}
	d.F = f
	d.Open = pick("open", 200)
	d.Claimed = pick("claimed", 200)
	d.Blocked = pick("blocked", 100)
	d.Closed = pick("done", 20)
	d.NewTask = form
	d.Err = formErr
	d.NewTaskOpen = formErr != ""
	if formErr == "" {
		d.Notice = noticeFrom(r)
	}
	d.HostIPs = w.knownIPs(ctx)

	wr.Header().Set("Content-Type", "text/html; charset=utf-8")
	wr.WriteHeader(code)
	if err := w.render(wr, r, "tasks", d); err != nil {
		w.log.Error("render tasks", "err", err)
	}
}

func (w *Web) knownIPs(ctx context.Context) []string {
	hosts, err := w.st.ListHosts(ctx, store.HostFilter{Sort: "ip", Limit: 2000})
	if err != nil {
		return nil
	}
	ips := make([]string, 0, len(hosts))
	for _, h := range hosts {
		ips = append(ips, h.IP)
	}
	return ips
}

type eventRow struct {
	model.Event
	HostIP string
}

type activityData struct {
	baseData
	Events []eventRow
	Kind   string
	HostQ  string
	Kinds  []string
}

func (w *Web) handleActivity(wr http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	kind := q.Get("kind")
	hostQ := q.Get("host")

	var hostID *int64
	if hostQ != "" {
		if id, err := w.st.HostIDByIP(ctx, hostQ); err == nil {
			hostID = &id
		} else if !errors.Is(err, store.ErrUnknownHost) && !errors.Is(err, sql.ErrNoRows) {
			http.Error(wr, err.Error(), 500)
			return
		} else {

			id := int64(-1)
			hostID = &id
		}
	}
	var kinds []string
	if kind != "" {
		kinds = []string{kind}
	}
	evs, err := w.st.ListEvents(ctx, 0, 200, kinds, hostID)
	if err != nil {
		http.Error(wr, err.Error(), 500)
		return
	}

	ipByID := map[int64]string{}
	var ids []any
	for _, e := range evs {
		if e.HostID != nil {
			ids = append(ids, *e.HostID)
		}
	}
	if len(ids) > 0 {
		rows, err := w.st.DB().Read.QueryContext(ctx,
			`SELECT id, ip FROM hosts WHERE id IN (`+inPlaceholders(len(ids))+`)`, ids...)
		if err == nil {
			for rows.Next() {
				var id int64
				var ip string
				if rows.Scan(&id, &ip) == nil {
					ipByID[id] = ip
				}
			}
			rows.Close()
		}
	}
	out := make([]eventRow, 0, len(evs))
	for _, e := range evs {
		r := eventRow{Event: e}
		if e.HostID != nil {
			r.HostIP = ipByID[*e.HostID]
		}
		out = append(out, r)
	}

	d := activityData{baseData: w.pageData(r, "activity")}
	d.Events = out
	d.Kind = kind
	d.HostQ = hostQ
	d.Kinds = store.EventKinds()
	if err := w.render(wr, r, "activity", d); err != nil {
		w.log.Error("render activity", "err", err)
	}
}

type webData struct {
	baseData
	F         store.WebFilter
	Matched   []model.WebResult
	Unmatched []model.WebResult
}

func (w *Web) handleWeb(wr http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	d := webData{baseData: w.pageData(r, "web")}
	d.F = store.WebFilter{
		Q:      q.Get("q"),
		Tech:   q.Get("tech"),
		Status: q.Get("status"),
	}
	res, err := w.st.ListWebResults(ctx, d.F)
	if err != nil {
		http.Error(wr, err.Error(), 500)
		return
	}

	for _, r := range res {
		if r.HostID == nil {
			d.Unmatched = append(d.Unmatched, r)
		} else {
			d.Matched = append(d.Matched, r)
		}
	}
	if err := w.render(wr, r, "web", d); err != nil {
		w.log.Error("render web", "err", err)
	}
}

type findingsData struct {
	baseData
	F        store.FindingFilter
	Findings []model.Finding
	States   []string
}

func (w *Web) handleFindings(wr http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := findingsData{baseData: w.pageData(r, "findings")}
	d.F.State = r.URL.Query().Get("state")
	if d.F.State != "" && !store.FindingStateValid(d.F.State) {
		d.F.State = ""
	}
	d.States = []string{"candidate", "confirmed", "reported", "rejected"}
	f, err := w.st.ListFindings(ctx, d.F)
	if err != nil {
		http.Error(wr, err.Error(), 500)
		return
	}
	d.Findings = f
	if err := w.render(wr, r, "findings", d); err != nil {
		w.log.Error("render findings", "err", err)
	}
}

func (w *Web) handleFindingState(wr http.ResponseWriter, r *http.Request, user string) error {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("bad finding id")
	}
	state := r.FormValue("state")
	if !store.FindingStateValid(state) {
		return fmt.Errorf("state must be confirmed|rejected|reported")
	}
	if err := w.st.EditFinding(r.Context(), user, id, store.FindingInput{State: state, Reason: r.FormValue("reason")}); err != nil {
		return err
	}
	if partial(r) {

		f, err := w.st.ListFindings(r.Context(), store.FindingFilter{})
		if err != nil {
			return err
		}
		for _, f := range f {
			if f.ID == id {
				d := struct {
					baseData
					Finding model.Finding
				}{baseData: w.pageData(r, "findings"), Finding: f}
				wr.Header().Set("Content-Type", "text/html; charset=utf-8")
				return w.tmpl.ExecuteTemplate(wr, "findingRow", d)
			}
		}
		return fmt.Errorf("finding %d not found after update", id)
	}
	hxRedirectBack(wr, r, "/findings")
	return nil
}
