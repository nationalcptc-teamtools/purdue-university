package cli

import (
	"context"
	"corkboard/internal/store"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"
)

func RunSearch(args []string) error { return RunSearchW(args, os.Stdout) }
func RunSearchW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	f := addClientFlags(fs)
	kind := fs.String("kind", "", "record type")
	cursor := fs.String("cursor", "", "next-page cursor")
	limit := fs.Int("limit", 50, "results per page (max 100)")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return usageError("usage: cork search QUERY [--kind TYPE] [--cursor CURSOR]")
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	q := url.Values{"q": {strings.Join(fs.Args(), " ")}, "kind": {*kind}, "cursor": {*cursor}, "limit": {strconv.Itoa(*limit)}}
	var page store.SearchPage
	if err = c.Workflow(context.Background(), "GET", "/api/v1/search?"+q.Encode(), nil, &page); err != nil {
		return err
	}
	if f.jsonOut() {
		return printJSON(w, page)
	}
	clean := func(s string) string {
		return strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return ' '
			}
			return r
		}, s)
	}
	var rows [][]string
	for _, h := range page.Results {
		rows = append(rows, []string{h.Kind, clean(h.ID), clean(h.Title), clean(h.Excerpt), h.Link})
	}
	table(w, []string{"TYPE", "ID", "TITLE", "MATCH", "LINK"}, rows)
	if page.NextCursor != "" {
		fmt.Fprintf(w, "Next cursor: %s\n", page.NextCursor)
	}
	return nil
}
