package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"corkboard/internal/client"
	"corkboard/internal/store"
)

func RunClaim(args []string) error { return RunClaimW(args, os.Stdout) }

func RunClaimW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("claim", flag.ContinueOnError)
	f := addClientFlags(fs)
	steal := fs.Bool("steal", false, "take the claim from its current owner")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("usage: cork claim IP|IP:PORT[/udp]|TASKID [--steal]")
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	arg := fs.Arg(0)
	ref, ok, err := serviceRef(context.Background(), c, arg)
	if err != nil {
		return err
	}
	if ok {
		var cc store.ClaimContext
		if err := c.Workflow(context.Background(), "POST", "/api/v1/claims", map[string]any{"target": ref, "action": "claim", "steal": *steal}, &cc); err != nil {
			return err
		}
		fmt.Fprintf(w, "claimed %s as %s\n", cc.Claim.Label, c.User())
		printClaimContext(w, cc)
		return nil
	}
	if id, err := strconv.ParseInt(arg, 10, 64); err == nil && id > 0 {
		t, err := c.PatchTask(context.Background(), id, "claimed", "", *steal)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "claimed task %d as %s\n", t.ID, c.User())
		return nil
	}
	if err := c.Claim(context.Background(), arg, *steal); err != nil {
		return err
	}
	fmt.Fprintf(w, "claimed %s as %s\n", arg, c.User())
	return nil
}

func RunRelease(args []string) error { return RunReleaseW(args, os.Stdout) }

func RunReleaseW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("release", flag.ContinueOnError)
	f := addClientFlags(fs)
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("usage: cork release IP|IP:PORT[/udp]|TASKID")
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	arg := fs.Arg(0)
	ref, ok, err := serviceRef(context.Background(), c, arg)
	if err != nil {
		return err
	}
	if ok {
		if err := c.Workflow(context.Background(), "POST", "/api/v1/claims", map[string]any{"target": ref, "action": "release"}, nil); err != nil {
			return err
		}
		fmt.Fprintf(w, "released %s\n", arg)
		return nil
	}
	if id, err := strconv.ParseInt(arg, 10, 64); err == nil && id > 0 {
		if _, err := c.PatchTask(context.Background(), id, "open", "", false); err != nil {
			return err
		}
		fmt.Fprintf(w, "released task %d\n", id)
		return nil
	}
	if err := c.Release(context.Background(), arg); err != nil {
		return err
	}
	fmt.Fprintf(w, "released %s\n", arg)
	return nil
}

func serviceRef(ctx context.Context, c *client.Client, arg string) (store.TargetRef, bool, error) {
	if strings.HasPrefix(arg, "service:") {
		ref, err := store.ParseTarget(arg)
		return ref, err == nil, err
	}
	if !strings.Contains(arg, ":") || net.ParseIP(arg) != nil {
		return store.TargetRef{}, false, nil
	}
	ip, port, proto, err := parseHostPort(arg)
	if err != nil {
		return store.TargetRef{}, false, err
	}
	d, err := c.GetHost(ctx, ip)
	if err != nil {
		return store.TargetRef{}, false, err
	}
	for _, sv := range d.Services {
		if sv.Port == port && sv.Proto == proto {
			return store.TargetRef{Kind: "service", ID: sv.ID}, true, nil
		}
	}
	return store.TargetRef{}, false, fmt.Errorf("%s has no %d/%s service", ip, port, proto)
}

func printClaimContext(w io.Writer, cc store.ClaimContext) {
	if cc.HostOwner != "" {
		fmt.Fprintf(w, "  host %s is coordinated by %s\n", cc.HostIP, cc.HostOwner)
	}
	for _, o := range cc.Others {
		fmt.Fprintf(w, "  %s: %s\n", o.Label, o.Owner)
	}
}
