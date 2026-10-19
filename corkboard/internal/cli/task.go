package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"corkboard/internal/client"
)

func RunTask(args []string) error { return RunTaskW(args, os.Stdout) }

func RunTaskW(args []string, w io.Writer) error {
	if len(args) < 1 {
		return usageError("usage: cork task list|done|block|add ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return runTaskListW(rest, w)
	case "done":
		return runTaskCloseW(rest, w, "done", false)
	case "block":
		return runTaskCloseW(rest, w, "blocked", true)
	case "add":
		return runTaskAddW(rest, w)
	default:
		return usageError("unknown task subcommand %q (want list, done, block, or add)", sub)
	}
}

func runTaskListW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("task list", flag.ContinueOnError)
	f := addClientFlags(fs)
	mine := fs.Bool("mine", false, "only my tasks")
	state := fs.String("state", "", "state filter: open|claimed|blocked|done|wontdo")
	priority := fs.Int("priority", 0, "priority filter (1-5)")
	host := fs.String("host", "", "host IP filter")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError("usage: cork task list [--mine] [--state S] [--priority N] [--host IP]")
	}
	if *state != "" && !storeTaskStateValid(*state) {
		return usageError("invalid --state %q", *state)
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	filter := client.TaskFilter{State: *state, Priority: *priority, Host: *host}
	if *mine {
		filter.Owner = c.User()
	}
	tasks, err := c.ListTasks(context.Background(), filter)
	if err != nil {
		return err
	}
	if f.jsonOut() {
		return printJSON(w, tasks)
	}
	rows := make([][]string, 0, len(tasks))
	for _, t := range tasks {
		who := t.Owner
		if who == "" {
			who = "-"
		}
		note := t.ClosedNote
		if note != "" {
			note = " " + note
		}
		rows = append(rows, []string{
			strconv.FormatInt(t.ID, 10),
			strconv.Itoa(t.Priority),
			t.State,
			t.HostIP,
			who,
			truncate(t.Title, 60) + note,
		})
	}
	table(w, []string{"ID", "PRIO", "STATE", "HOST", "OWNER", "TITLE"}, rows)
	return nil
}

func storeTaskStateValid(s string) bool {
	switch s {
	case "open", "claimed", "blocked", "done", "wontdo":
		return true
	}
	return false
}

func runTaskCloseW(args []string, w io.Writer, state string, noteRequired bool) error {
	verb := "done"
	if state == "blocked" {
		verb = "block"
	}
	fs := flag.NewFlagSet("task "+verb, flag.ContinueOnError)
	f := addClientFlags(fs)
	note := fs.String("m", "", "closing note (required for block)")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("usage: cork task %s ID [-m NOTE]", verb)
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil || id <= 0 {
		return usageError("task id must be a positive integer")
	}
	if noteRequired && *note == "" {
		return usageError("cork task block requires -m REASON")
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	t, err := c.PatchTask(context.Background(), id, state, *note, false)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "task %d %s (%s)\n", t.ID, t.State, t.Title)
	return nil
}

func runTaskAddW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("task add", flag.ContinueOnError)
	f := addClientFlags(fs)
	priority := fs.Int("priority", 3, "priority 1-5 (default 3)")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return usageError("usage: cork task add IP[:PORT[/udp]] \"title\" [--priority N]")
	}
	ip, title := fs.Arg(0), fs.Arg(1)
	port, proto := 0, ""
	if strings.Contains(ip, ":") {
		var err error
		if ip, port, proto, err = parseHostPort(ip); err != nil {
			return err
		}
	}
	if *priority < 1 || *priority > 5 {
		return usageError("priority must be 1-5")
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	t, err := c.CreateTask(context.Background(), ip, port, proto, title, "", nil, *priority)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "task %d created: %s\n", t.ID, t.Title)
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
