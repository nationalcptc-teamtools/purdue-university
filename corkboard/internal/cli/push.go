package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"corkboard/internal/client"
	"corkboard/internal/ingest"
	"corkboard/internal/ingest/gowitness"
	"corkboard/internal/ingest/nmap"
	"corkboard/internal/ingest/nuclei"
	"corkboard/internal/ingest/nxc"
)

func RunPush(args []string) error { return RunPushW(args, os.Stdout) }

func RunPushW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	f := addClientFlags(fs)
	fileType := fs.String("type", "auto", "input type: auto|nmap|nxc|gowitness|nuclei|manual")
	dryRun := fs.Bool("dry-run", false, "print what would be sent without uploading")
	shotsDir := fs.String("screenshots", "", "directory of gowitness screenshots to upload (file names must match the JSONL)")
	vantage := fs.String("vantage", "", "source machine or foothold that produced the scan")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	paths := fs.Args()
	if len(paths) == 0 {
		return usageError("usage: cork push FILE... [--type auto|nmap|nxc|gowitness|nuclei] [--screenshots DIR] [--dry-run]")
	}

	var batches []*ingest.Batch
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		if fi.IsDir() {

			nb, err := nxc.ReadWorkspace(ctx0(), p)
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			for _, b := range nb {
				b.Warnings = append(b.Warnings, "source: "+p)
				batches = append(batches, b.Batch)
			}
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		t := *fileType
		if t == "auto" {
			t = detectKind(data, p)
			if t == "" {
				return fmt.Errorf("can't tell what %s is (use --type)", p)
			}
		}
		switch t {
		case "nmap", "masscan":
			b, err := nmap.Parse(bytes.NewReader(data))
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			b.Warnings = append(b.Warnings, "source: "+p)
			sum := sha256.Sum256(data)
			b.Run.SourceSHA = hex.EncodeToString(sum[:])
			b.Run.SourceName = filepath.Base(p)
			b.Run.Vantage = *vantage
			batches = append(batches, b)
		case "nxc":
			nb, err := nxc.ReadFile(ctx0(), p)
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			nb.Warnings = append(nb.Warnings, "source: "+p)
			batches = append(batches, nb.Batch)
		case "gowitness":
			b, err := gowitness.Parse(bytes.NewReader(data))
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			b.Warnings = append(b.Warnings, "source: "+p)
			batches = append(batches, b)
		case "nuclei":
			b, err := nuclei.Parse(bytes.NewReader(data))
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			b.Warnings = append(b.Warnings, "source: "+p)
			batches = append(batches, b)
		case "manual":
			var b ingest.Batch
			if err := json.Unmarshal(data, &b); err != nil {
				return fmt.Errorf("%s: not a manual batch JSON: %w", p, err)
			}
			if b.Version != ingest.BatchVersion {
				return fmt.Errorf("%s: batch version %d, want %d", p, b.Version, ingest.BatchVersion)
			}
			if b.Run.Kind == "" {
				b.Run.Kind = "manual"
			}
			b.Warnings = append(b.Warnings, "source: "+p)
			batches = append(batches, &b)
		default:
			return usageError("unknown --type %q (auto|nmap|nxc|gowitness|nuclei|manual)", t)
		}
	}

	if *dryRun {
		for _, b := range batches {
			printDryRun(w, b)
		}
		return nil
	}

	c, err := f.buildClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	for _, b := range batches {
		res, err := c.PushBatch(ctx, b)
		if err != nil {
			return err
		}
		printPushSummary(w, c, b, res)
	}

	if *shotsDir != "" {
		refs := map[string]bool{}
		for _, b := range batches {
			if b.Run.Kind != "gowitness" {
				continue
			}
			for _, wb := range b.WebResults {
				if wb.ScreenshotSHA != "" {
					refs[wb.ScreenshotSHA] = true
				}
			}
		}
		names := make([]string, 0, len(refs))
		for n := range refs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			img, err := os.ReadFile(filepath.Join(*shotsDir, filepath.Base(name)))
			if err != nil {
				return fmt.Errorf("screenshot %s: %w", name, err)
			}
			sha, _, err := c.UploadScreenshot(ctx, filepath.Base(name), img)
			if err != nil {
				return fmt.Errorf("uploading screenshot %s: %w", name, err)
			}
			fmt.Fprintf(w, "screenshot %s → %s\n", name, sha[:12])
		}
		if n := len(names); n > 0 {
			fmt.Fprintf(w, "%d screenshot%s uploaded from %s\n", n, plural(n), *shotsDir)
		}
	}
	return nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func detectKind(data []byte, path string) string {
	trimmed := bytes.TrimLeft(data, " \t\r\n\xef\xbb\xbf")
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<nmaprun")) {
		if bytes.Contains(trimmed, []byte(`scanner="masscan"`)) {
			return "masscan"
		}
		return "nmap"
	}

	if bytes.HasPrefix(trimmed, []byte("SQLite format 3\x00")) && nxc.Protocol(filepath.Base(path)) != "" {
		return "nxc"
	}
	if gowitness.Detect(data) {
		return "gowitness"
	}
	if nuclei.Detect(data) {
		return "nuclei"
	}
	return ""
}

func ctx0() context.Context { return context.Background() }

func printDryRun(w io.Writer, b *ingest.Batch) {
	services := 0
	for _, h := range b.Hosts {
		services += len(h.Services)
	}
	fmt.Fprintf(w, "dry-run %s: %d hosts, %d services, no upload\n", b.Run.Kind, len(b.Hosts), services)
	for _, warn := range b.Warnings {
		fmt.Fprintf(w, "  warning: %s\n", warn)
	}
}

func printPushSummary(w io.Writer, c *client.Client, b *ingest.Batch, res ingest.Result) {
	hosts := len(b.Hosts)
	services := 0
	for _, h := range b.Hosts {
		services += len(h.Services)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s: %d hosts (%d new), %d services (%d new)", b.Run.Kind, hosts, res.NewHosts, services, res.NewServices)
	if res.Duplicate {
		sb.WriteString(" (duplicate run, nothing changed)")
	}
	fmt.Fprintln(w, sb.String())
	if n := len(res.OutOfScope); n > 0 {
		plural := ""
		if n > 1 {
			plural = "s"
		}
		fmt.Fprintf(w, "  ⚠ %d out-of-scope host%s: %s\n", n, plural, strings.Join(res.OutOfScope, ", "))
	}
	for _, warn := range res.Warnings {
		if strings.HasPrefix(warn, "source: ") {
			fmt.Fprintf(w, "  %s\n", warn)
			continue
		}
		fmt.Fprintf(w, "  warning: %s\n", warn)
	}
}
