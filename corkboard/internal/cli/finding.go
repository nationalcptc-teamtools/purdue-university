package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"corkboard/internal/model"
	"corkboard/internal/store"
)

func RunFinding(args []string) error { return RunFindingW(args, os.Stdout) }

func RunFindingW(args []string, w io.Writer) error {
	if len(args) < 1 {
		return usageError("usage: cork finding list|confirm|reject ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add", "show", "edit", "merge", "reopen":
		return runFindingDetailW(sub, rest, w)
	case "list":
		return runFindingListW(rest, w)
	case "confirm":
		return runFindingStateW(rest, w, "confirm", "confirmed")
	case "reject":
		return runFindingStateW(rest, w, "reject", "rejected")
	default:
		return usageError("unknown finding subcommand %q (want list, confirm, or reject)", sub)
	}
}

func runFindingListW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("finding list", flag.ContinueOnError)
	f := addClientFlags(fs)
	state := fs.String("state", "", "state filter: candidate|confirmed|rejected|reported")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError("usage: cork finding list [--state S]")
	}
	if *state != "" && !findingStateValid(*state) {
		return usageError("invalid --state %q", *state)
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	findings, err := c.ListFindings(context.Background(), *state)
	if err != nil {
		return err
	}
	if f.jsonOut() {
		return printJSON(w, findings)
	}
	rows := make([][]string, 0, len(findings))
	for _, fnd := range findings {
		rows = append(rows, []string{
			strconv.FormatInt(fnd.ID, 10),
			fnd.Severity,
			fnd.State,
			fnd.Source,
			findingHosts(fnd),
			truncate(fnd.Title, 60),
		})
	}
	table(w, []string{"ID", "SEVERITY", "STATE", "SOURCE", "HOSTS", "TITLE"}, rows)
	return nil
}

func findingHosts(f model.Finding) string {
	ips := make([]string, 0, len(f.Hosts))
	for _, h := range f.Hosts {
		ips = append(ips, h.IP)
	}
	if len(ips) == 0 {
		return "-"
	}
	return strings.Join(ips, ",")
}

func runFindingStateW(args []string, w io.Writer, verb, state string) error {
	fs := flag.NewFlagSet("finding "+verb, flag.ContinueOnError)
	f := addClientFlags(fs)
	reason := fs.String("reason", "", "reason for rejecting a finding")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("usage: cork finding %s ID", verb)
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil || id <= 0 {
		return usageError("finding id must be a positive integer")
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	if err := c.Workflow(context.Background(), "PATCH", fmt.Sprintf("/api/v1/findings/%d", id), store.FindingInput{State: state, Reason: *reason}, nil); err != nil {
		return err
	}
	fmt.Fprintf(w, "finding %d %s\n", id, state)
	return nil
}

func findingStateValid(s string) bool {
	switch s {
	case "candidate", "confirmed", "rejected", "reported":
		return true
	}
	return false
}

func runFindingDetailW(sub string, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("finding "+sub, flag.ContinueOnError)
	f := addClientFlags(fs)
	title := fs.String("title", "", "finding title")
	severity := fs.String("severity", "info", "severity")
	description := fs.String("description", "", "impact/description")
	target := fs.String("target", "", "space-separated host:ID/service:ID/application:ID")
	evidence := fs.String("evidence", "", "evidence excerpt")
	state := fs.String("state", "", "state")
	reason := fs.String("reason", "", "reason")
	report := fs.String("report-ref", "", "report reference")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	in := store.FindingInput{Title: *title, Severity: *severity, Description: *description, Evidence: *evidence, State: *state, Reason: *reason, ReportRef: *report}

	if sub != "add" {
		explicit := false
		fs.Visit(func(v *flag.Flag) {
			if v.Name == "severity" {
				explicit = true
			}
		})
		if !explicit {
			in.Severity = ""
		}
	}
	for _, v := range strings.Fields(*target) {
		t, err := store.ParseTarget(v)
		if err != nil {
			return err
		}
		in.Targets = append(in.Targets, t)
	}
	if sub == "add" {
		if fs.NArg() != 0 {
			return usageError("finding add --title TEXT --target host:ID --severity high")
		}
		id, err := c.RecordFinding(ctx, in)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "finding %d created\n", id)
		return nil
	}
	if fs.NArg() < 1 {
		return usageError("finding %s ID", sub)
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil || id <= 0 {
		return usageError("invalid finding ID")
	}
	if sub == "show" {
		var d store.FindingDetail
		if err = c.FindingDetail(ctx, id, &d); err != nil {
			return err
		}
		return printJSON(w, d)
	}
	if sub == "merge" {
		if fs.NArg() != 2 {
			return usageError("finding merge SOURCE DESTINATION")
		}
		in.MergeInto, err = strconv.ParseInt(fs.Arg(1), 10, 64)
		if err != nil {
			return err
		}
	}
	if sub == "reopen" {
		in.State = "candidate"
	}
	if err = c.Workflow(ctx, "PATCH", fmt.Sprintf("/api/v1/findings/%d", id), in, nil); err != nil {
		return err
	}
	fmt.Fprintf(w, "finding %d updated\n", id)
	return nil
}
