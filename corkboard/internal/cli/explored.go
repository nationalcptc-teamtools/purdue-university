package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func RunPriority(args []string) error { return RunPriorityW(args, os.Stdout) }

func RunPriorityW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("priority", flag.ContinueOnError)
	f := addClientFlags(fs)
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return usageError("usage: cork priority IP 1|2|3")
	}
	p, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(fs.Arg(1)), "P"))
	if err != nil || p < 1 || p > 3 {
		return usageError("priority must be 1, 2, or 3")
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	if err := c.SetPriority(context.Background(), fs.Arg(0), p); err != nil {
		return err
	}
	fmt.Fprintf(w, "%s: P%d\n", fs.Arg(0), p)
	return nil
}

func RunExplored(args []string) error { return RunExploredW(args, os.Stdout) }

func RunExploredW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("explored", flag.ContinueOnError)
	f := addClientFlags(fs)
	undo := fs.Bool("undo", false, "clear the explored mark")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("usage: cork explored IP:PORT[/udp] [--undo]")
	}
	ip, port, proto, err := parseHostPort(fs.Arg(0))
	if err != nil {
		return err
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	d, err := c.GetHost(ctx, ip)
	if err != nil {
		return err
	}
	for _, s := range d.Services {
		if s.Port == port && s.Proto == proto {
			if err := c.SetServiceExplored(ctx, s.ID, !*undo); err != nil {
				return err
			}
			if *undo {
				fmt.Fprintf(w, "%s:%d/%s reopened\n", ip, port, proto)
			} else {
				fmt.Fprintf(w, "%s:%d/%s explored\n", ip, port, proto)
			}
			return nil
		}
	}
	return fmt.Errorf("%s has no %d/%s service", ip, port, proto)
}

func parseHostPort(v string) (ip string, port int, proto string, err error) {
	proto = "tcp"
	if i := strings.LastIndex(v, "/"); i >= 0 {
		v, proto = v[:i], strings.ToLower(v[i+1:])
	}
	i := strings.LastIndex(v, ":")
	if i <= 0 || (proto != "tcp" && proto != "udp") {
		return "", 0, "", usageError("expected IP:PORT or IP:PORT/udp, got %q", v)
	}
	port, err = strconv.Atoi(v[i+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, "", usageError("invalid port in %q", v)
	}
	return v[:i], port, proto, nil
}
