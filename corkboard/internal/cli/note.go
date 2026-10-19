package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func RunLog(args []string) error { return RunLogW(args, os.Stdout) }

func RunLogW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	f := addClientFlags(fs)
	worked := fs.Bool("worked", false, "it worked")
	failed := fs.Bool("failed", false, "it did not work")
	command := fs.String("cmd", "", "the command you ran")
	outputFile := fs.String("output", "", "file with the command's output (- for stdin)")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return usageError("usage: cork log IP[:PORT[/udp]] \"what you did\" [--worked|--failed] [--cmd CMD] [--output FILE|-]")
	}
	if *worked && *failed {
		return usageError("pass --worked or --failed, not both")
	}
	target, text := fs.Arg(0), fs.Arg(1)
	in := map[string]any{}
	ip := target
	if strings.Contains(target, ":") {
		var port int
		var proto string
		var err error
		if ip, port, proto, err = parseHostPort(target); err != nil {
			return err
		}
		in["port"], in["proto"] = port, proto
	}
	stdinUsed := false
	if text == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		text, stdinUsed = strings.TrimSpace(string(data)), true
	}
	if text == "" {
		return usageError("log text is empty")
	}
	if *outputFile != "" {
		if *outputFile == "-" && stdinUsed {
			return usageError("stdin is already the log text; pass --output FILE")
		}
		var data []byte
		var err error
		if *outputFile == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(*outputFile)
		}
		if err != nil {
			return err
		}
		in["output"] = string(data)
	}
	if *worked {
		in["outcome"] = "worked"
	} else if *failed {
		in["outcome"] = "failed"
	}
	in["body"], in["command"] = text, *command
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	if err := c.AddLog(context.Background(), ip, in); err != nil {
		return err
	}
	fmt.Fprintf(w, "logged on %s\n", target)
	return nil
}

func RunTag(args []string) error { return RunTagW(args, os.Stdout) }

func RunTagW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("tag", flag.ContinueOnError)
	f := addClientFlags(fs)
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return usageError("usage: cork tag IP +tag [-tag]...")
	}
	ip := fs.Arg(0)
	var add, remove []string
	for _, a := range fs.Args()[1:] {
		switch {
		case strings.HasPrefix(a, "+") && len(a) > 1:
			add = append(add, a[1:])
		case strings.HasPrefix(a, "-") && len(a) > 1:
			remove = append(remove, a[1:])
		default:
			return usageError("tag arguments must start with + or -: %q", a)
		}
	}
	if len(add) == 0 && len(remove) == 0 {
		return usageError("nothing to do: pass at least one +tag or -tag")
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	if err := c.SetTags(context.Background(), ip, add, remove); err != nil {
		return err
	}
	var parts []string
	if len(add) > 0 {
		parts = append(parts, "+"+strings.Join(add, " +"))
	}
	if len(remove) > 0 {
		parts = append(parts, "-"+strings.Join(remove, " -"))
	}
	fmt.Fprintf(w, "%s: %s\n", ip, strings.Join(parts, " "))
	return nil
}
