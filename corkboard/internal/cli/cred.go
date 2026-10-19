package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"corkboard/internal/client"
	"corkboard/internal/model"
)

func RunCred(args []string) error { return RunCredW(args, os.Stdout) }

func RunCredW(args []string, w io.Writer) error {
	if len(args) == 0 {
		return usageError("usage: cork cred add|list|where|reveal")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return runCredAddW(rest, w)
	case "list":
		return runCredListW(rest, w)
	case "where":
		return runCredWhereW(rest, w)
	case "reveal":
		return runCredRevealW(rest, w)
	default:
		return usageError("cred subcommand must be add|list|where|reveal, got %q", sub)
	}
}

func runCredAddW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("cred add", flag.ContinueOnError)
	f := addClientFlags(fs)
	secretType := fs.String("type", "password", "secret type: password|ntlm|aes|ssh_key|ticket|hash_uncracked|other")
	notes := fs.String("notes", "", "notes")
	on := fs.String("on", "", "repeatable: IP:protocol:level (smb|ldap|mssql|winrm|rdp|ssh:invalid|valid|admin)")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return usageError("usage: cork cred add DOMAIN\\USER SECRET --type T [--on IP:PROTO:LEVEL ...]")
	}
	domain, user, ok := splitUser(fs.Arg(0))
	if !ok {
		return usageError("first arg must be DOMAIN\\USER (use \"USER\" for no domain)")
	}
	in := client.CredInput{
		Domain:     domain,
		Username:   user,
		Secret:     fs.Arg(1),
		SecretType: *secretType,
		Notes:      *notes,
	}
	if *on != "" {
		for _, spec := range strings.Split(*on, " ") {
			parts := strings.Split(spec, ":")
			if len(parts) != 3 {
				return usageError("--on expects IP:protocol:level (e.g. 10.0.0.10:smb:admin)")
			}
			in.Access = append(in.Access, struct {
				IP       string `json:"ip"`
				Protocol string `json:"protocol"`
				Level    string `json:"level"`
			}{IP: parts[0], Protocol: parts[1], Level: parts[2]})
		}
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	id, err := c.AddCred(context.Background(), in)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "cred %d: %s (%s)\n", id, model.CredName(in.Domain, in.Username), in.SecretType)
	return nil
}

func runCredListW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("cred list", flag.ContinueOnError)
	f := addClientFlags(fs)
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	creds, err := c.ListCreds(context.Background())
	if err != nil {
		return err
	}
	if f.jsonOut() {
		return printJSON(w, creds)
	}
	if len(creds) == 0 {
		fmt.Fprintln(w, "(no credentials)")
		return nil
	}
	fmt.Fprintf(w, "%-4s %-32s %-24s %-10s %-12s %s\n", "ID", "USER", "SECRET", "TYPE", "SOURCE", "VALID-ON / ADMIN-ON")
	for _, cr := range creds {
		name := model.CredName(cr.Domain, cr.Username)
		var valid, admin []string
		for _, a := range cr.Access {
			if a.Level == "admin" {
				admin = append(admin, a.IP)
			} else if a.Level == "valid" {
				valid = append(valid, a.IP)
			}
		}
		sort.Strings(valid)
		sort.Strings(admin)
		fmt.Fprintf(w, "%-4d %-32s %-24s %-10s %-12s %s / %s\n",
			cr.ID, truncate(name, 32), cr.Secret, cr.SecretType, cr.Source, joinComma(valid), joinComma(admin))
	}
	return nil
}

func runCredWhereW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("cred where", flag.ContinueOnError)
	f := addClientFlags(fs)
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("usage: cork cred where DOMAIN\\USER [--json]")
	}
	domain, user, ok := splitUser(fs.Arg(0))
	if !ok {
		return usageError("arg must be DOMAIN\\USER (or \"USER\" for no domain)")
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	creds, err := c.ListCreds(context.Background())
	if err != nil {
		return err
	}
	var matches []model.Cred
	for _, cr := range creds {
		if cr.Domain == domain && cr.Username == user {
			matches = append(matches, cr)
		}
	}
	if len(matches) == 0 {
		return fmt.Errorf("no credential %s", model.CredName(domain, user))
	}
	if f.jsonOut() {
		return printJSON(w, matches)
	}
	for _, cr := range matches {
		if len(cr.Access) == 0 {
			fmt.Fprintf(w, "%s: no recorded access\n", model.CredName(cr.Domain, cr.Username))
			continue
		}
		type row struct {
			ip, proto, level string
		}
		var rows []row
		for _, a := range cr.Access {
			rows = append(rows, row{a.IP, a.Protocol, a.Level})
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].ip != rows[j].ip {
				return rows[i].ip < rows[j].ip
			}
			return rows[i].proto < rows[j].proto
		})
		for _, r := range rows {
			fmt.Fprintf(w, "%-16s %-8s %s\n", r.ip, r.proto, r.level)
		}
	}
	return nil
}

func runCredRevealW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("cred reveal", flag.ContinueOnError)
	f := addClientFlags(fs)
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("usage: cork cred reveal ID")
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil || id <= 0 {
		return usageError("cred id must be a positive integer")
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	secret, err := c.RevealCred(context.Background(), id)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, secret)
	return nil
}

func splitUser(s string) (domain, user string, ok bool) {
	if i := strings.LastIndex(s, "\\"); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return "", s, true
}

func joinComma(list []string) string {
	if len(list) == 0 {
		return "-"
	}
	return strings.Join(list, ", ")
}
