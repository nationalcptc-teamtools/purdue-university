package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"corkboard/internal/model"
)

func RunHost(args []string) error { return RunHostW(args, os.Stdout) }

func RunHostW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("host", flag.ContinueOnError)
	f := addClientFlags(fs)
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("usage: cork host IP")
	}
	ip := fs.Arg(0)
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	d, err := c.GetHost(context.Background(), ip)
	if err != nil {
		return err
	}
	if f.jsonOut() {
		return printJSON(w, d)
	}

	h := d.Host
	fmt.Fprintf(w, "%s  %s  status=%s zone=%s", h.IP, h.OS, h.Status, h.Zone)
	if h.Owner != "" {
		fmt.Fprintf(w, "  owner=%s", h.Owner)
	}
	fmt.Fprintln(w)
	if h.Domain != "" {
		fmt.Fprintf(w, "  domain: %s\n", h.Domain)
	}
	if h.MAC != "" {
		vendor := ""
		if h.MACVendor != "" {
			vendor = " (" + h.MACVendor + ")"
		}
		fmt.Fprintf(w, "  mac:    %s%s\n", h.MAC, vendor)
	}
	if len(h.Hostnames) > 0 {
		names := make([]string, 0, len(h.Hostnames))
		for _, n := range h.Hostnames {
			names = append(names, n.Name)
		}
		fmt.Fprintf(w, "  names:  %s\n", strings.Join(names, ", "))
	}
	fmt.Fprintf(w, "  first seen: %s   last seen: %s   priority: %d\n",
		ms(h.FirstSeen), ms(h.LastSeen), h.Priority)
	if len(h.Tags) > 0 {
		fmt.Fprintf(w, "  tags:   %s\n", strings.Join(h.Tags, ", "))
	}

	if len(d.Services) > 0 {
		fmt.Fprintln(w, "\nServices:")
		rows := make([][]string, 0, len(d.Services))
		for _, s := range d.Services {
			rows = append(rows, []string{
				fmt.Sprintf("%d/%s", s.Port, s.Proto), s.State, s.Name, s.Version, s.Product,
			})
		}
		table(w, []string{"PORT", "STATE", "NAME", "VERSION", "PRODUCT"}, rows)
	}

	if len(d.Web) > 0 {
		fmt.Fprintln(w, "\nWeb:")
		for _, web := range d.Web {
			fmt.Fprintf(w, "  %s  %s", web.URL, web.Title)
			if web.Failed {
				fmt.Fprintf(w, "  (failed: %s)", web.FailedReason)
			}
			fmt.Fprintln(w)
		}
	}

	if len(d.Creds) > 0 {
		fmt.Fprintln(w, "\nCreds:")
		for _, cred := range d.Creds {
			fmt.Fprintf(w, "  %s  %s  %s\n", model.CredName(cred.Domain, cred.Username), cred.SecretType, cred.Secret)
		}
	}

	if len(d.Notes) > 0 {
		fmt.Fprintln(w, "\nLog (newest first):")
		for _, n := range d.Notes {
			where := "host"
			if n.Service != "" {
				where = n.Service
			}
			outcome := ""
			if n.Outcome != "" {
				outcome = " [" + n.Outcome + "]"
			}
			fmt.Fprintf(w, "  %s  %-9s %s%s: %s\n", ms(n.CreatedAt), where, n.Author, outcome, firstLine(n.Body))
			if n.Command != "" {
				fmt.Fprintf(w, "      $ %s\n", firstLine(n.Command))
			}
		}
	}

	if len(d.Compromises) > 0 {
		fmt.Fprintln(w, "\nCompromises:")
		for _, comp := range d.Compromises {
			how := comp.ViaText
			if how == "" {
				how = comp.ByUser
			}
			fmt.Fprintf(w, "  %s  %s  %s\n", ms(comp.At), comp.Level, how)
		}
	}
	return nil
}

func ms(v int64) string {
	if v == 0 {
		return "-"
	}
	return time.UnixMilli(v).Format("2006-01-02 15:04:05")
}

func firstLine(s string) string {
	for i, r := range s {
		if r == '\n' {
			return s[:i]
		}
	}
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}
