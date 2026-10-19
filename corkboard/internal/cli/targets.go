package cli

import (
	"context"
	"flag"
	"io"
	"os"
)

func RunTargets(args []string) error { return RunTargetsW(args, os.Stdout) }

func RunTargetsW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("targets", flag.ContinueOnError)
	f := addClientFlags(fs)
	hf := addHostFilterFlags(fs, true)
	format := fs.String("format", "ip", "output format: ip|hostport|url|nmap")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError("unexpected arguments: %v", fs.Args())
	}
	if *format != "ip" && *format != "hostport" && *format != "url" && *format != "nmap" {
		return usageError("format must be ip|hostport|url|nmap")
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	out, err := c.Targets(context.Background(), hf.filter(), *format)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, out)
	return err
}
