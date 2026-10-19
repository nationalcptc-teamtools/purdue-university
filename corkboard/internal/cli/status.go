package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"corkboard/internal/client"
)

func RunStatus(args []string) error { return RunStatusW(args, os.Stdout) }

func RunStatusW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	f := addClientFlags(fs)
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	ctx := context.Background()

	all, err := c.ListHosts(ctx, client.HostFilter{})
	if err != nil {
		return err
	}
	statuses := map[string]int{}
	inScope, outScope := 0, 0
	for _, h := range all {
		statuses[h.Status]++
		if h.Zone == "out" {
			outScope++
		} else {
			inScope++
		}
	}
	mine, err := c.ListHosts(ctx, client.HostFilter{Owner: c.User()})
	if err != nil {
		return err
	}
	tasks, err := c.ListTasks(ctx, client.TaskFilter{})
	if err != nil {
		return err
	}
	taskStates := map[string]int{}
	myTasks := 0
	for _, t := range tasks {
		taskStates[t.State]++
		if t.Owner == c.User() && t.State == "claimed" {
			myTasks++
		}
	}

	if f.jsonOut() {
		return printJSON(w, map[string]any{
			"hosts":        len(all),
			"statuses":     statuses,
			"in_scope":     inScope,
			"out_of_scope": outScope,
			"my_claims":    mine,
			"tasks":        taskStates,
			"my_tasks":     myTasks,
			"user":         c.User(),
		})
	}

	fmt.Fprintf(w, "Corkboard status (as %s)\n", c.User())
	if len(statuses) == 0 {
		fmt.Fprintln(w, "  no hosts yet - push a scan!")
	} else {
		fmt.Fprintf(w, "  hosts: %d in-scope", inScope)
		for i, s := range statusOrder(statuses) {
			if i == 0 {
				fmt.Fprintf(w, " (%d %s", statuses[s], s)
			} else {
				fmt.Fprintf(w, ", %d %s", statuses[s], s)
			}
		}
		fmt.Fprintln(w, ")")
	}
	if outScope > 0 {
		fmt.Fprintf(w, "  SCOPE ALARM: %d out-of-scope host(s) in scans (hidden from default views)\n", outScope)
	}
	if len(mine) > 0 {
		ips := make([]string, 0, len(mine))
		for _, h := range mine {
			ips = append(ips, h.IP)
		}
		fmt.Fprintf(w, "  my claims: %s\n", strings.Join(ips, ", "))
	} else {
		fmt.Fprintln(w, "  my claims: (none) - cork claim IP")
	}
	fmt.Fprintf(w, "  tasks: %d open, %d claimed (%d mine), %d blocked - cork task list\n",
		taskStates["open"], taskStates["claimed"], myTasks, taskStates["blocked"])
	return nil
}

func statusOrder(m map[string]int) []string {
	order := []string{"untouched", "in_progress", "compromised", "false_positive"}
	out := make([]string, 0, len(order))
	for _, s := range order {
		if m[s] > 0 {
			out = append(out, s)
		}
	}
	var extra []string
	for s := range m {
		if !in(order, s) {
			extra = append(extra, s)
		}
	}
	for i := 1; i < len(extra); i++ {
		for j := i; j > 0 && extra[j] < extra[j-1]; j-- {
			extra[j], extra[j-1] = extra[j-1], extra[j]
		}
	}
	return append(out, extra...)
}

func in(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
