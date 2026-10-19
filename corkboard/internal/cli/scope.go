package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"corkboard/internal/scope"
)

func RunScope(args []string) error { return RunScopeW(args, os.Stdout) }

func RunScopeW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("scope", flag.ContinueOnError)
	scopeFile := fs.String("scope", "scope.yaml", "scope file (scope.yaml or scope.yml)")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return usageError("usage: cork scope check TARGET... | cork scope exclude [--scope FILE]")
	}
	sub := fs.Arg(0)

	sc, err := loadScopeFile(*scopeFile)
	if err != nil {
		return err
	}

	switch sub {
	case "exclude":
		if fs.NArg() != 1 {
			return usageError("usage: cork scope exclude [--scope FILE]")
		}
		fmt.Fprint(w, sc.NmapExclude())
		return nil
	case "check":
		targets := fs.Args()[1:]
		if len(targets) == 0 {
			return usageError("give at least one target: IP, CIDR, range, or hostname (a file path reads one target per line)")
		}
		results, err := expandTargets(sc, targets)
		if err != nil {
			return err
		}
		out := 0
		for _, r := range results {
			fmt.Fprintf(w, "%-28s %-8s %s\n", r.Value, r.Zone, r.Reason)
			if r.Zone == scope.ZoneOut {
				out++
			}
		}
		fmt.Fprintf(w, "%d target(s), %d out-of-scope\n", len(results), out)
		if out > 0 {
			return usageError("%d target(s) are OUT OF SCOPE - do not scan them", out)
		}
		return nil
	default:
		return usageError("unknown scope subcommand %q (want check or exclude)", sub)
	}
}

func loadScopeFile(name string) (*scope.Scope, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		alt := strings.TrimSuffix(name, ".yaml") + ".yml"
		data, err = os.ReadFile(alt)
		if err != nil {
			return nil, fmt.Errorf("cannot read scope file: %w", err)
		}
	}
	return scope.Load(data)
}

func expandTargets(sc *scope.Scope, args []string) ([]scope.TargetResult, error) {
	var targets []string
	for _, a := range args {
		if info, err := os.Stat(a); err == nil && info.Mode().IsRegular() {
			data, err := os.ReadFile(a)
			if err != nil {
				return nil, err
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, line)
				}
			}
		} else {
			targets = append(targets, a)
		}
	}
	return sc.Check(targets...), nil
}
