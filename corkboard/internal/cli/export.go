package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"corkboard/internal/client"
)

func RunOwned(args []string) error { return RunOwnedW(args, os.Stdout) }

func RunOwnedW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("owned", flag.ContinueOnError)
	f := addClientFlags(fs)
	level := fs.String("level", "", "compromise level: user|admin|system|domain_admin")
	viaFinding := fs.Int64("via-finding", 0, "finding id this compromise came from")
	viaCred := fs.Int64("via-cred", 0, "credential id used for this compromise")
	via := fs.String("m", "", "free-text 'how'")
	fs.StringVar(via, "message", "", "free-text 'how' (-m)")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("usage: cork owned IP --level user|admin|system|domain_admin [--via-finding ID] [--via-cred ID] -m \"how\"")
	}
	ip := fs.Arg(0)
	if *level == "" {
		return usageError("--level is required (user|admin|system|domain_admin)")
	}
	if *via == "" && *viaFinding == 0 && *viaCred == 0 {
		return usageError("provide -m \"how\", --via-finding, or --via-cred")
	}
	in := client.SetOwnedInput{Level: *level, ViaText: *via}
	if *viaFinding > 0 {
		in.ViaFindingID = viaFinding
	}
	if *viaCred > 0 {
		in.ViaCredID = viaCred
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	if err := c.SetOwned(context.Background(), ip, in); err != nil {
		return err
	}
	fmt.Fprintf(w, "%s marked compromised as %s\n", ip, *level)
	return nil
}

var exportKinds = []string{
	"hosts.csv", "services.csv", "creds.csv", "findings.csv",
	"all.json", "appendix.md", "narrative.md", "bloodhound-owned.txt",
}

func RunExport(args []string) error { return RunExportW(args, os.Stdout) }

func RunExportW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	f := addClientFlags(fs)
	outPath := fs.String("o", "", "write to FILE instead of stdout")
	reveal := fs.Bool("reveal", false, "ignored: creds.csv always includes secrets")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("usage: cork export %s [-o FILE]", joinKinds(exportKinds))
	}
	kind := fs.Arg(0)
	ok := false
	for _, k := range exportKinds {
		if k == kind {
			ok = true
			break
		}
	}
	if !ok {
		return usageError("unknown export kind %q (want %s)", kind, joinKinds(exportKinds))
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	body, err := c.Export(context.Background(), kind, *reveal)
	if err != nil {
		return err
	}
	if *outPath != "" {
		if err := os.WriteFile(*outPath, []byte(body), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(w, "wrote %s (%d bytes)\n", *outPath, len(body))
		return nil
	}
	io.WriteString(w, body)
	return nil
}

func joinKinds(kinds []string) string {
	s := ""
	for i, k := range kinds {
		if i > 0 {
			s += " | "
		}
		s += k
	}
	return s
}
