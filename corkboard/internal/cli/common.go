package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"corkboard/internal/client"
	"corkboard/internal/config"
)

type clientFlags struct {
	server   *string
	pass     *string
	user     *string
	json     *bool
	insecure *bool
}

func addClientFlags(fs *flag.FlagSet) clientFlags {
	return clientFlags{
		server:   fs.String("server", "", "server URL (overrides client config and $CORK_SERVER)"),
		pass:     fs.String("passphrase", "", "team passphrase (overrides client config and $CORK_PASSPHRASE)"),
		user:     fs.String("user", "", "your name (overrides client config and $CORK_USER)"),
		json:     fs.Bool("json", false, "machine-readable JSON output"),
		insecure: fs.Bool("insecure", false, "SKIP all TLS verification (dangerous)"),
	}
}

func (f clientFlags) buildClient() (*client.Client, error) {
	cfg, err := config.LoadClient()
	if err != nil {
		return nil, err
	}
	if *f.server != "" {
		cfg.Server = *f.server
	}
	if *f.pass != "" {
		cfg.Passphrase = *f.pass
	}
	if *f.user != "" {
		cfg.User = *f.user
	}
	if *f.insecure {
		fmt.Fprintln(os.Stderr, "WARNING: --insecure skips ALL TLS verification; only use on a trusted network.")
	}
	return client.New(client.Options{
		ServerURL:  cfg.Server,
		Passphrase: cfg.Passphrase,
		User:       cfg.User,
		Pin:        cfg.TLSFingerprint,
		Insecure:   *f.insecure,
	})
}

func (f clientFlags) jsonOut() bool { return *f.json }

func table(w io.Writer, headers []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	if len(headers) > 0 {
		line := make([]string, len(headers))
		copy(line, headers)
		_, _ = tw.Write([]byte(strings.Join(line, "\t") + "\n"))
	}
	for _, r := range rows {
		_, _ = tw.Write([]byte(strings.Join(r, "\t") + "\n"))
	}
	_ = tw.Flush()
}

func usageError(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

func exitCodeOf(err error) int {
	if e, ok := err.(interface{ ExitCode() int }); ok {
		return e.ExitCode()
	}
	return 1
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func ExitCode(err error) int { return exitCodeOf(err) }

func reorderArgs(fs *flag.FlagSet, args []string) []string {
	var flags, positionals []string
	for i := 0; i < len(args); {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			positionals = append(positionals, a)
			i++
			continue
		}
		name := strings.TrimLeft(a, "-")
		if idx := strings.Index(name, "="); idx >= 0 {
			name = name[:idx]
		}
		f := fs.Lookup(name)
		if f == nil {
			positionals = append(positionals, a)
			i++
			continue
		}
		flags = append(flags, a)
		i++
		if !strings.Contains(a, "=") {
			isBool, ok := f.Value.(interface{ IsBoolFlag() bool })
			if (!ok || !isBool.IsBoolFlag()) && i < len(args) {
				flags = append(flags, args[i])
				i++
			}
		}
	}
	return append(flags, positionals...)
}
