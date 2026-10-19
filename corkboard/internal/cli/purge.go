package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
)

func RunPurge(args []string) error { return RunPurgeW(args, os.Stdout) }

func RunPurgeW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("purge", flag.ContinueOnError)
	f := addClientFlags(fs)
	confirm := fs.String("confirm", "", "engagement name to confirm the purge")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 0 || *confirm == "" {
		return usageError("usage: cork purge --confirm ENGAGEMENT_NAME")
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	out, err := c.Purge(context.Background(), *confirm)
	if err != nil {
		return err
	}
	n := 0
	if r, ok := out["removed"].([]any); ok {
		n = len(r)
	}
	fmt.Fprintf(w, "purged all data (removed %d paths); stop and restart the server\n", n)
	return nil
}
