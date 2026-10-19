package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"corkboard/internal/auth"
	"corkboard/internal/config"
)

func RunPassphrase(args []string) error { return RunPassphraseW(args, os.Stdout) }

func RunPassphraseW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("passphrase", flag.ContinueOnError)
	dataDir := fs.String("data", "cork-data", "data directory holding server.yaml")
	passFlag := fs.String("passphrase", "", "new team passphrase (prompted for when omitted)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError("usage: cork passphrase [--data DIR] [--passphrase PASS]")
	}
	path := filepath.Join(*dataDir, "server.yaml")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s: %w (run cork init first)", path, err)
	}
	pass, err := passphraseFrom(*passFlag, true)
	if err != nil {
		return err
	}
	hash, err := auth.Hash(pass)
	if err != nil {
		return err
	}
	if err := config.SetPassphraseHash(path, hash); err != nil {
		return err
	}
	fmt.Fprintf(w, "Team passphrase updated in %s.\n", path)
	fmt.Fprintln(w, "Restart cork serve, then everyone runs cork login again.")
	return nil
}
