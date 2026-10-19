package web

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"corkboard/internal/accessgraph"
	"corkboard/internal/store"
)

type accessQuery struct {
	Node, Kind, Level, Actor, AsOfText string
	Cred                               int64
	AsOf                               int64
	Known, Derived                     bool
	Depth                              int
}

func parseAccessQuery(q url.Values) (accessQuery, error) {
	a := accessQuery{Node: q.Get("node"), Kind: q.Get("kind"), Level: q.Get("level"), Actor: q.Get("actor"), AsOfText: q.Get("as_of"),
		Known: q.Get("known") == "1", Derived: q.Get("derived") != "0", Depth: 1}
	if v := q.Get("cred"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return a, fmt.Errorf("invalid credential ID")
		}
		a.Cred = n
	}
	if v := q.Get("depth"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 4 {
			return a, fmt.Errorf("depth must be 1-4")
		}
		a.Depth = n
	}
	if a.AsOfText != "" {
		t, err := time.Parse(time.RFC3339, a.AsOfText)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04", a.AsOfText)
		}
		if err != nil {
			return a, fmt.Errorf("as of: use 2026-10-24T14:30 (UTC) or RFC3339")
		}
		a.AsOf = t.UnixMilli()
	}
	return a, nil
}

func (a accessQuery) values() url.Values {
	v := url.Values{}
	for k, s := range map[string]string{"node": a.Node, "kind": a.Kind, "level": a.Level, "actor": a.Actor} {
		if s != "" {
			v.Set(k, s)
		}
	}
	if a.Cred > 0 {
		v.Set("cred", strconv.FormatInt(a.Cred, 10))
	}
	if a.AsOf > 0 {
		v.Set("as_of", time.UnixMilli(a.AsOf).UTC().Format(time.RFC3339))
	}
	if a.Known {
		v.Set("known", "1")
	}
	if !a.Derived {
		v.Set("derived", "0")
	}
	if a.Depth > 1 {
		v.Set("depth", strconv.Itoa(a.Depth))
	}
	return v
}

func (w *Web) accessEdges(ctx context.Context, a accessQuery, asOf int64) ([]store.AccessEdge, error) {
	f := store.LedgerFilter{AsOf: asOf, Known: a.Known, Node: a.Node, CredID: a.Cred, Kind: a.Kind, Level: a.Level, Actor: a.Actor, Derived: a.Derived}
	edges, err := w.st.Ledger(ctx, f)
	if err != nil || a.Node == "" || a.Depth <= 1 {
		return edges, err
	}
	f.Node = ""
	all, err := w.st.Ledger(ctx, f)
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	frontier := map[string]bool{}
	for _, e := range edges {
		keep[e.Key] = true
		frontier[e.Src], frontier[e.Dst] = true, true
	}
	for hop := 1; hop < a.Depth; hop++ {
		next := map[string]bool{}
		for _, e := range all {
			if !keep[e.Key] && (frontier[e.Src] && e.Src != "" || frontier[e.Dst]) {
				keep[e.Key] = true
				edges = append(edges, e)
				next[e.Src], next[e.Dst] = true, true
			}
		}
		frontier = next
	}
	return edges, nil
}

func (w *Web) handleAccess(wr http.ResponseWriter, r *http.Request) {
	a, err := parseAccessQuery(r.URL.Query())
	d := struct {
		baseData
		Q          accessQuery
		Edges      []store.AccessEdge
		Graph      accessgraph.Graph
		SVG        template.HTML
		Prev, Next string
		Export     string
		Expand     string
		NowLink    string
		Vantages   []store.Vantage
		Tunnels    []store.Tunnel
	}{baseData: w.pageData(r, "access"), Q: a}
	if err != nil {
		d.Err = err.Error()
	} else {

		history, err := w.accessEdges(r.Context(), a, 0)
		if err != nil {
			http.Error(wr, err.Error(), 400)
			return
		}

		ceil := func(t int64) int64 { return (t + 999) / 1000 * 1000 }
		step := func(t int64) string {
			b := a
			b.AsOf = ceil(t)
			return "/access?" + b.values().Encode()
		}
		for _, t := range accessgraph.Times(history) {
			switch {
			case a.AsOf == 0:
				if d.Next == "" {
					d.Next = step(t)
				}
			case ceil(t) < a.AsOf:
				d.Prev = step(t)
			case ceil(t) > a.AsOf && d.Next == "":
				d.Next = step(t)
			}
		}
		d.Edges = history
		if a.AsOf > 0 {
			if d.Edges, err = w.accessEdges(r.Context(), a, a.AsOf); err != nil {
				http.Error(wr, err.Error(), 400)
				return
			}
		}
		d.Graph = accessgraph.Build(d.Edges)
		d.SVG = template.HTML(d.Graph.SVG("Access graph", true, false))
		d.Export = a.values().Encode()
		now := a
		now.AsOf = 0
		d.NowLink = "/access?" + now.values().Encode()
		if a.Node != "" && a.Depth < 4 {
			b := a
			b.Depth++
			d.Expand = "/access?" + b.values().Encode()
		}
	}
	d.Vantages, _ = w.st.Vantages(r.Context())
	d.Tunnels, _ = w.st.Tunnels(r.Context())
	if err := w.render(wr, r, "access", d); err != nil {
		w.log.Error("render access", "err", err)
	}
}

func (w *Web) accessExport(format string) http.HandlerFunc {
	return func(wr http.ResponseWriter, r *http.Request) { w.handleAccessExport(wr, r, format) }
}

func (w *Web) handleAccessExport(wr http.ResponseWriter, r *http.Request, format string) {
	a, err := parseAccessQuery(r.URL.Query())
	if err != nil {
		http.Error(wr, err.Error(), 400)
		return
	}
	edges, err := w.accessEdges(r.Context(), a, a.AsOf)
	if err != nil {
		http.Error(wr, err.Error(), 400)
		return
	}
	title := "Access history"
	if a.AsOf > 0 {
		title += " as of " + time.UnixMilli(a.AsOf).UTC().Format("2006-01-02 15:04 UTC")
	}
	var body []byte
	switch format {
	case "svg":
		wr.Header().Set("Content-Type", "image/svg+xml")
		body = accessgraph.Build(edges).SVG(title, false, true)
	case "json":
		wr.Header().Set("Content-Type", "application/json")
		body, _ = json.MarshalIndent(accessgraph.Build(edges), "", "  ")
	case "md":
		wr.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		body = accessgraph.Markdown(title, edges)
	default:
		http.NotFound(wr, r)
		return
	}
	wr.Header().Set("Content-Disposition", `attachment; filename="access-graph.`+format+`"`)
	_, _ = wr.Write(body)
}
