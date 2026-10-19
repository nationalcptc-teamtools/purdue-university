package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func RunEvidence(args []string) error { return RunEvidenceW(args, os.Stdout) }
func RunEvidenceW(args []string, w io.Writer) error {
	if len(args) == 0 || args[0] != "add" {
		return usageError("usage: cork evidence add --finding ID|--target host:ID --file FILE|--external REF [--caption TEXT]")
	}
	fs := flag.NewFlagSet("evidence add", flag.ContinueOnError)
	f := addClientFlags(fs)
	finding := fs.String("finding", "", "finding ID")
	target := fs.String("target", "", "target reference")
	file := fs.String("file", "", "PNG/JPEG or UTF-8 text file")
	external := fs.String("external", "", "external reference")
	caption := fs.String("caption", "", "evidence caption")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*finding == "" && *target == "") || ((*file == "") == (*external == "")) {
		return usageError("provide a finding/target and exactly one of --file or --external")
	}
	var data []byte
	var name string
	if *file != "" {
		in, err := os.Open(*file)
		if err != nil {
			return err
		}
		defer in.Close()
		data, err = io.ReadAll(io.LimitReader(in, (5<<20)+1))
		if err != nil {
			return err
		}
		if len(data) > 5<<20 {
			return usageError("evidence exceeds 5 MiB")
		}
		name = filepath.Base(*file)
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	id, err := c.UploadEvidence(context.Background(), *finding, *target, *caption, *external, name, data)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "evidence %d attached\n", id)
	return nil
}
