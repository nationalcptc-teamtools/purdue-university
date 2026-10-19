package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"

	"corkboard/internal/archive"
)

func RunArchive(args []string) error { return RunArchiveW(args, os.Stdout) }
func RunArchiveW(args []string, w io.Writer) error {
	if len(args) == 0 {
		return usageError("usage: cork archive export|inspect|restore [flags]")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	switch args[0] {
	case "export":
		fs := flag.NewFlagSet("archive export", flag.ContinueOnError)
		flags := addClientFlags(fs)
		output := fs.String("output", "", "new .cork.zip file to create")
		if err := fs.Parse(reorderArgs(fs, args[1:])); err != nil {
			return err
		}
		if fs.NArg() != 0 || *output == "" {
			return usageError("usage: cork archive export --output FILE.cork.zip [client flags]")
		}
		if _, err := os.Lstat(*output); err == nil {
			return fmt.Errorf("output already exists: %s", *output)
		} else if !os.IsNotExist(err) {
			return err
		}
		c, err := flags.buildClient()
		if err != nil {
			return err
		}
		f, err := os.CreateTemp(filepath.Dir(*output), ".cork-download-*.zip")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		defer f.Close()
		if err = c.ExportArchive(ctx, f); err != nil {
			return err
		}
		if err = f.Sync(); err != nil {
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		m, err := archive.Inspect(ctx, f.Name())
		if err != nil {
			return fmt.Errorf("download verification failed: %w", err)
		}
		if err = archive.PublishFile(f.Name(), *output); err != nil {
			return err
		}
		fmt.Fprintf(w, "Wrote verified snapshot %s (engagement %s, event %d)\n", *output, m.EngagementID, m.EventID)
		return nil
	case "inspect":
		fs := flag.NewFlagSet("archive inspect", flag.ContinueOnError)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return usageError("usage: cork archive inspect FILE.cork.zip")
		}
		m, err := archive.Inspect(ctx, fs.Arg(0))
		if err != nil {
			return err
		}
		return printJSON(w, m)
	case "restore":
		fs := flag.NewFlagSet("archive restore", flag.ContinueOnError)
		dest := fs.String("data", "", "fresh destination data directory")
		pass := fs.String("passphrase", "", "new destination passphrase (otherwise prompted)")
		if err := fs.Parse(reorderArgs(fs, args[1:])); err != nil {
			return err
		}
		if fs.NArg() != 1 || *dest == "" {
			return usageError("usage: cork archive restore FILE.cork.zip --data NEW_DIR [--passphrase PASS]")
		}
		if _, err := os.Lstat(*dest); err == nil {
			return fmt.Errorf("destination already exists: %s", *dest)
		} else if !os.IsNotExist(err) {
			return err
		}
		value, err := passphraseWithEnv(*pass, "CORK_RESTORE_PASSPHRASE", true)
		if err != nil {
			return err
		}
		m, err := archive.Restore(ctx, fs.Arg(0), *dest, value)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "Restored %s into %s. Integrations are disabled.\nRun: cork serve --data %s\n", m.EngagementName, *dest, *dest)
		return nil
	default:
		return usageError("unknown archive command %q (want export, inspect, restore)", args[0])
	}
}
