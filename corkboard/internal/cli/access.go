package cli

import (
	"context"
	"corkboard/internal/store"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"time"
)

const accessUsage = `usage:
  cork access list [--as-of T] [--known] [--node KEY] [--cred ID] [--kind K]
  cork access add KIND --to KEY [--from KEY] [--level L] [--via EDGE] [--cred ID] [--finding ID] [--evidence ID] [--at T] [-m NOTE]
  cork access correct EDGE KIND --to KEY [--from KEY] ... --reason R
  cork access end EDGE --reason R [--at T]
  cork access vantage NAME --type operator|foothold|network [--host IP] [-m NOTE]
  cork access vantages
  cork access tunnel --through IP --vantage NAME [--listen ADDR] [--dest NET] [--at T] [-m NOTE]
  cork access tunnel-end ID --reason R [--at T]
  cork access tunnels
KIND: reach, auth, shell, cred_found, cred_used. KEY: IP, host:ID,
service:ID, application:ID, cred:ID, or vantage:NAME. No --from means the
source is unknown. T is RFC3339.`

func RunAccess(args []string) error { return RunAccessW(args, os.Stdout) }
func RunAccessW(args []string, w io.Writer) error {
	if len(args) == 0 {
		return usageError(accessUsage)
	}
	sub := args[0]
	fs := flag.NewFlagSet("access "+sub, flag.ContinueOnError)
	f := addClientFlags(fs)
	asOf := fs.String("as-of", "", "show the chain as it stood at this time")
	known := fs.Bool("known", false, "with --as-of: what Corkboard knew then, not when things happened")
	node := fs.String("node", "", "only edges touching this node")
	kind := fs.String("kind", "", "edge kind filter")
	from := fs.String("from", "", "source node (omit if unknown)")
	to := fs.String("to", "", "destination node")
	level := fs.String("level", "", "auth: valid|admin; shell: user|admin|system|domain_admin")
	via := fs.Int64("via", 0, "edge that made this possible")
	cred := fs.Int64("cred", 0, "credential ID")
	finding := fs.Int64("finding", 0, "finding ID")
	evidence := fs.Int64("evidence", 0, "evidence ID")
	at := fs.String("at", "", "when it happened (RFC3339; omitted means unknown, or now for end)")
	note := fs.String("m", "", "note")
	reason := fs.String("reason", "", "correction or end reason")
	vkind := fs.String("type", "", "vantage type: operator|foothold|network")
	hostIP := fs.String("host", "", "host IP of a foothold vantage")
	viaIP := fs.String("through", "", "host IP the tunnel runs through")
	vantage := fs.String("vantage", "", "vantage name the tunnel provides")
	listen := fs.String("listen", "", "tunnel listener, e.g. 127.0.0.1:1080")
	dest := fs.String("dest", "", "what the tunnel reaches, e.g. 10.0.20.0/24")
	if err := fs.Parse(reorderArgs(fs, args[1:])); err != nil {
		return err
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	optTime := func() (*int64, error) {
		if *at == "" {
			return nil, nil
		}
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			return nil, fmt.Errorf("--at must be RFC3339, e.g. 2026-10-24T10:35:00-04:00")
		}
		ms := t.UnixMilli()
		return &ms, nil
	}
	opt := func(v int64) *int64 {
		if v <= 0 {
			return nil
		}
		return &v
	}
	edgeInput := func(k string) (store.EdgeInput, error) {
		occurred, err := optTime()
		return store.EdgeInput{Kind: k, Src: *from, Dst: *to, Level: *level, ViaEdgeID: opt(*via), CredID: opt(*cred), FindingID: opt(*finding), EvidenceID: opt(*evidence), Note: *note, OccurredAt: occurred}, err
	}
	argID := func(i int) (int64, error) {
		if fs.NArg() <= i {
			return 0, usageError(accessUsage)
		}
		n, err := strconv.ParseInt(fs.Arg(i), 10, 64)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid ID %q", fs.Arg(i))
		}
		return n, nil
	}
	var out map[string]any
	switch sub {
	case "list":
		q := url.Values{"node": {*node}, "kind": {*kind}, "level": {*level}}
		if *cred > 0 {
			q.Set("cred", strconv.FormatInt(*cred, 10))
		}
		if *asOf != "" {
			q.Set("as_of", *asOf)
		}
		if *known {
			q.Set("known", "1")
		}
		var res struct {
			Edges []store.AccessEdge `json:"edges"`
		}
		if err = c.Workflow(ctx, "GET", "/api/v1/access?"+q.Encode(), nil, &res); err != nil {
			return err
		}
		if f.jsonOut() {
			return printJSON(w, res)
		}
		printLedger(w, res.Edges)
		return nil
	case "add":
		if fs.NArg() != 1 {
			return usageError(accessUsage)
		}
		in, err := edgeInput(fs.Arg(0))
		if err != nil {
			return err
		}
		if err = c.Workflow(ctx, "POST", "/api/v1/access", in, &out); err != nil {
			return err
		}
		fmt.Fprintf(w, "recorded edge %v\n", out["id"])
		return nil
	case "correct":
		id, err := argID(0)
		if err != nil {
			return err
		}
		if fs.NArg() != 2 {
			return usageError(accessUsage)
		}
		in, err := edgeInput(fs.Arg(1))
		if err != nil {
			return err
		}
		in.Corrects, in.CorrectionReason = &id, *reason
		if err = c.Workflow(ctx, "POST", "/api/v1/access", in, &out); err != nil {
			return err
		}
		fmt.Fprintf(w, "edge %v corrects edge %d\n", out["id"], id)
		return nil
	case "end", "tunnel-end":
		id, err := argID(0)
		if err != nil {
			return err
		}
		occurred, err := optTime()
		if err != nil {
			return err
		}
		path := fmt.Sprintf("/api/v1/access/%d/end", id)
		if sub == "tunnel-end" {
			path = fmt.Sprintf("/api/v1/tunnels/%d/end", id)
		}
		if err = c.Workflow(ctx, "POST", path, map[string]any{"reason": *reason, "occurred_at": occurred}, nil); err != nil {
			return err
		}
		fmt.Fprintf(w, "ended %d\n", id)
		return nil
	case "vantage":
		if fs.NArg() != 1 {
			return usageError(accessUsage)
		}
		if err = c.Workflow(ctx, "POST", "/api/v1/vantages", store.Vantage{Name: fs.Arg(0), Kind: *vkind, HostIP: *hostIP, Note: *note}, nil); err != nil {
			return err
		}
		fmt.Fprintf(w, "added vantage %s; push scans from it with cork push --vantage %s\n", fs.Arg(0), fs.Arg(0))
		return nil
	case "vantages":
		var vs []store.Vantage
		if err = c.Workflow(ctx, "GET", "/api/v1/vantages", nil, &vs); err != nil {
			return err
		}
		if f.jsonOut() {
			return printJSON(w, vs)
		}
		var rows [][]string
		for _, v := range vs {
			rows = append(rows, []string{v.Name, v.Kind, v.HostIP, v.Note})
		}
		table(w, []string{"NAME", "KIND", "HOST", "NOTE"}, rows)
		return nil
	case "tunnel":
		started, err := optTime()
		if err != nil {
			return err
		}
		in := store.Tunnel{ViaHostIP: *viaIP, Vantage: *vantage, Listener: *listen, Destination: *dest, StartedAt: started, Note: *note}
		if err = c.Workflow(ctx, "POST", "/api/v1/tunnels", in, &out); err != nil {
			return err
		}
		fmt.Fprintf(w, "recorded tunnel %v\n", out["id"])
		return nil
	case "tunnels":
		var ts []store.Tunnel
		if err = c.Workflow(ctx, "GET", "/api/v1/tunnels", nil, &ts); err != nil {
			return err
		}
		if f.jsonOut() {
			return printJSON(w, ts)
		}
		var rows [][]string
		for _, t := range ts {
			rows = append(rows, []string{strconv.FormatInt(t.ID, 10), t.State, t.Owner, t.ViaHostIP, t.Listener, t.Destination, t.Vantage})
		}
		table(w, []string{"ID", "STATE", "OWNER", "VIA", "LISTENER", "DEST", "VANTAGE"}, rows)
		return nil
	}
	return usageError(accessUsage)
}

func printLedger(w io.Writer, edges []store.AccessEdge) {
	stamp := func(ms int64) string { return time.UnixMilli(ms).Format("01-02 15:04") }
	var rows [][]string
	for _, e := range edges {
		when := "time unknown"
		if e.OccurredAt != nil {
			when = stamp(*e.OccurredAt)
		}
		id := e.Key
		if e.Derived {
			id += " (derived)"
		}
		state := e.State
		if e.SupersededBy != nil {
			state = fmt.Sprintf("corrected by %d", *e.SupersededBy)
		} else if e.EndedAt != nil {
			state += " " + stamp(*e.EndedAt)
		}
		rows = append(rows, []string{when, id, e.Kind, e.Level, e.SrcLabel, e.DstLabel, e.Actor, state})
	}
	table(w, []string{"WHEN", "EDGE", "KIND", "LEVEL", "FROM", "TO", "BY", "STATE"}, rows)
}
