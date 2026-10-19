package cli

import (
	"context"
	"corkboard/internal/store"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"
)

func RunChanges(args []string) error { return RunChangesW(args, os.Stdout) }
func RunChangesW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("changes", flag.ContinueOnError)
	f := addClientFlags(fs)
	since := fs.String("since", "", "window: duration like 8h or an RFC3339 time")
	all := fs.Bool("all", false, "include your own changes (standup view)")
	ack := fs.Bool("ack", false, "mark the printed changes read")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError("usage: cork changes [--since 8h] [--all] [--ack]")
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	q := url.Values{}
	if *since != "" {
		q.Set("since", *since)
	}
	if *all {
		q.Set("all", "1")
	}
	ctx := context.Background()
	var d store.Digest
	if err = c.Workflow(ctx, "GET", "/api/v1/changes?"+q.Encode(), nil, &d); err != nil {
		return err
	}
	if f.jsonOut() {
		if err = printJSON(w, d); err != nil {
			return err
		}
	} else {
		printDigest(w, d)
	}
	if *ack && d.Total > 0 {
		if err = c.Workflow(ctx, "POST", "/api/v1/changes/ack", map[string]int64{"through": d.Through}, nil); err != nil {
			return err
		}
		if !f.jsonOut() {
			fmt.Fprintf(w, "marked %d changes read\n", d.Total)
		}
	}
	return nil
}

func printDigest(w io.Writer, d store.Digest) {
	if d.Total == 0 {
		fmt.Fprintln(w, "nothing new")
		return
	}
	clean := func(s string) string {
		return strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return ' '
			}
			return r
		}, s)
	}
	stamp := func(ms int64) string { return time.UnixMilli(ms).Format("01-02 15:04") }
	for _, g := range d.Groups {
		fmt.Fprintf(w, "== %s (%d)\n", g.Title, g.Count)
		for _, it := range g.Items {
			when := stamp(it.At)
			if it.OccurredAt != nil && *it.OccurredAt != it.At {
				when = stamp(*it.OccurredAt) + " (recorded " + when + ")"
			}
			host := ""
			if it.HostIP != "" {
				host = " [" + it.HostIP + "]"
			}
			fmt.Fprintf(w, "  %s %s: %s%s\n", when, it.Actor, clean(it.Summary), host)
		}
		if g.Count > len(g.Items) {
			fmt.Fprintf(w, "  ... %d more\n", g.Count-len(g.Items))
		}
	}
}
