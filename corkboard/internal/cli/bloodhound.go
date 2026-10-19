package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"corkboard/internal/client"
)

func RunBloodHound(args []string) error { return RunBloodHoundW(args, os.Stdout) }

func RunBloodHoundW(args []string, w io.Writer) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Fprintln(w, "Usage: cork bloodhound status|check|sync|owned IDENTITY [flags]")
		fmt.Fprintln(w, "  status  Show connection setup and per-identity sync results")
		fmt.Fprintln(w, "  check   Test the configured BloodHound API without changing it")
		fmt.Fprintln(w, "  sync    Queue ownership updates and retry failed mappings")
		fmt.Fprintln(w, "  owned   Record an owned account (USER@DOMAIN or SID)")
		fmt.Fprintln(w, "          Use --kind Computer --ip IP for an already compromised host")
		fmt.Fprintln(w, "Global flags: --server URL --passphrase PASS --user NAME --json")
		fmt.Fprintln(w, "Offline fallback: cork export bloodhound-owned.txt")
		return nil
	}
	if len(args) == 0 {
		return usageError("usage: cork bloodhound status|check|sync|owned IDENTITY [--kind Computer|User] [--ip IP]")
	}
	sub := args[0]
	if sub != "status" && sub != "check" && sub != "sync" && sub != "owned" {
		return usageError("unknown bloodhound subcommand %q", sub)
	}
	fs := flag.NewFlagSet("bloodhound "+sub, flag.ContinueOnError)
	f := addClientFlags(fs)
	kind := fs.String("kind", "User", "owned identity kind: Computer or User")
	ip := fs.String("ip", "", "compromised host IP for a Computer mapping")
	if err := fs.Parse(reorderArgs(fs, args[1:])); err != nil {
		return err
	}
	if (sub == "owned" && fs.NArg() != 1) || (sub != "owned" && fs.NArg() != 0) {
		return usageError("usage: cork bloodhound %s%s", sub, map[bool]string{true: " IDENTITY [--kind Computer|User] [--ip IP]"}[sub == "owned"])
	}
	if sub == "owned" {
		if *kind != "User" && *kind != "Computer" {
			return usageError("--kind must be Computer or User")
		}
		if strings.TrimSpace(fs.Arg(0)) == "" {
			return usageError("identity must not be empty")
		}
		if *kind == "User" && *ip != "" {
			return usageError("--ip applies only to Computer identities")
		}
		if *kind == "Computer" && *ip == "" {
			return usageError("--ip is required for Computer identities")
		}
		if *ip != "" {
			if _, err := netip.ParseAddr(*ip); err != nil {
				return usageError("--ip must be an IP address")
			}
		}
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	switch sub {
	case "status":
		out, err := c.BloodHoundStatus(ctx)
		if err != nil {
			return err
		}
		if f.jsonOut() {
			return printJSON(w, out)
		}
		fmt.Fprintf(w, "BloodHound enabled: %t; configured: %t; auto sync: %t\n", out.Enabled, out.Configured, out.AutoSync)
		if out.URL != "" {
			fmt.Fprintln(w, "URL:", out.URL)
		}
		if out.Error != "" {
			fmt.Fprintln(w, "Error:", out.Error)
		}
		if out.LastError != "" {
			fmt.Fprintln(w, "Last sync error:", out.LastError)
		}
		rows := make([][]string, 0, len(out.Targets))
		for _, t := range out.Targets {
			lastErr := t.LastError
			if lastErr == "" {
				lastErr = t.Error
			}
			rows = append(rows, []string{strconv.FormatInt(t.ID, 10), t.Kind, t.Identity, t.IP, t.State, lastErr})
		}
		table(w, []string{"ID", "KIND", "IDENTITY", "IP", "STATUS", "ERROR"}, rows)
	case "check":
		out, err := c.BloodHoundCheck(ctx)
		if err != nil {
			return err
		}
		if f.jsonOut() {
			return printJSON(w, out)
		}
		fmt.Fprintf(w, "BloodHound %s (%s)\n", out.Version, out.Mode)
	case "sync":
		queued, err := c.BloodHoundSync(ctx)
		if err != nil {
			return err
		}
		if f.jsonOut() {
			return printJSON(w, map[string]bool{"queued": queued})
		}
		fmt.Fprintf(w, "Synchronization queued: %t\n", queued)
	case "owned":
		out, err := c.BloodHoundOwned(ctx, client.BloodHoundTargetInput{Kind: *kind, Identity: strings.TrimSpace(fs.Arg(0)), IP: *ip})
		if err != nil {
			return err
		}
		if f.jsonOut() {
			return printJSON(w, out)
		}
		fmt.Fprintf(w, "Saved %s ownership mapping: %s (%s)\n", out.Kind, out.Identity, out.State)
	}
	return nil
}
