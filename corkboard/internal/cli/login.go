package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"corkboard/internal/client"
	"corkboard/internal/config"
)

func RunLogin(args []string) error { return RunLoginW(args, os.Stdout) }

func RunLoginW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	server := fs.String("server", "", "server URL, e.g. https://10.0.10.250:8443")
	passFlag := fs.String("passphrase", "", "team passphrase (prompted for when omitted)")
	user := fs.String("user", "", "your display name")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if *server == "" || *user == "" {
		return usageError("usage: cork login --server URL --user NAME [--passphrase PASS]")
	}
	if fs.NArg() != 0 {
		return usageError("unexpected arguments: %v", fs.Args())
	}
	pass, err := passphraseFrom(*passFlag, false)
	if err != nil {
		return err
	}

	c, err := client.New(client.Options{ServerURL: *server, Passphrase: pass, User: *user})
	if err != nil {
		return err
	}
	ctx := context.Background()
	fingerprint, who, err := c.Login(ctx)
	if err != nil {
		return err
	}
	if err := c.SetPin(fingerprint); err != nil {
		return err
	}

	if _, err := c.Whoami(ctx); err != nil {
		return fmt.Errorf("post-pin verification failed: %w", err)
	}

	cfg := &config.Client{Server: *server, Passphrase: pass, User: *user, TLSFingerprint: fingerprint}
	if err := cfg.Save(); err != nil {
		return err
	}

	fmt.Fprintf(w, "logged in as %s to %s\n", *user, *server)
	fmt.Fprintf(w, "  engagement: %s (server %s)\n", who.Engagement, who.Version)
	switch {
	case fingerprint != "":
		fmt.Fprintf(w, "  pinned TLS fingerprint (self-signed server): %s\n", fingerprint)
	case strings.HasPrefix(strings.ToLower(*server), "http://"):
		fmt.Fprintln(w, "  plain HTTP, no TLS (fine on a trusted network)")
	default:
		fmt.Fprintln(w, "  TLS verified by a trusted certificate authority (no pin needed)")
	}
	return nil
}
