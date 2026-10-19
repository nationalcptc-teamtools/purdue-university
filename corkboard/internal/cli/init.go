package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"corkboard/examples"
	"corkboard/internal/auth"
	"corkboard/internal/config"
)

func RunInit(args []string) error { return RunInitW(args, os.Stdout) }

func RunInitW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dataDir := fs.String("data", "cork-data", "data directory to create")
	engagement := fs.String("engagement", "New engagement", "engagement name")
	passFlag := fs.String("passphrase", "", "team passphrase (prompted for when omitted)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v (usage: cork init [--data DIR] [--engagement NAME] [--passphrase PASS])", fs.Args())
	}

	abs, err := filepath.Abs(*dataDir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(abs, "server.yaml")); err == nil {
		return fmt.Errorf("%s is already initialized (server.yaml exists)", abs)
	}

	pass, err := passphraseFrom(*passFlag, true)
	if err != nil {
		return err
	}
	passHash, err := auth.Hash(pass)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(abs, 0o700); err != nil {
		return err
	}

	secret, err := config.GenerateSessionSecret()
	if err != nil {
		return err
	}

	cfg := config.DefaultServer(*engagement)
	cfg.PassphraseHash = passHash
	cfg.SessionSecret = secret
	if err := cfg.Save(filepath.Join(abs, "server.yaml")); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(abs, "scope.yaml"), examples.ScopeYAML, 0o644); err != nil {
		return err
	}

	fmt.Fprintf(w, "cork: created data dir %s\n", abs)
	for _, name := range []string{"server.yaml", "scope.yaml"} {
		fmt.Fprintf(w, "  %s\n", name)
	}
	fmt.Fprintln(w, "\nTeam passphrase set. Only a salted hash is stored; tell teammates in person.")
	fmt.Fprintln(w, "\nNext steps:")
	fmt.Fprintf(w, "  1. Edit %s/scope.yaml from the rules of engagement\n", abs)
	fmt.Fprintf(w, "  2. cork serve --data %s\n", abs)
	fmt.Fprintf(w, "  3. Teammates: cork login --server https://<host>:8443 --user <name>\n")
	return nil
}
