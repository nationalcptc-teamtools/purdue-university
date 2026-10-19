package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"corkboard/internal/client"
)

type hostFilterFlags struct {
	tag     *string
	status  *string
	port    *int
	service *string
	owner   *string
	query   *string
}

func addHostFilterFlags(fs *flag.FlagSet, queryFlag bool) hostFilterFlags {
	f := hostFilterFlags{}
	f.tag = fs.String("tag", "", "filter by tag")
	f.status = fs.String("status", "", "filter by status: untouched|in_progress|done|compromised|locked")
	f.port = fs.Int("port", 0, "filter to hosts with this open port")
	f.service = fs.String("service", "", "filter by service name (e.g. http)")
	f.owner = fs.String("owner", "", "filter by claiming owner")
	if queryFlag {
		f.query = fs.String("q", "", "free-text query (IP, hostname, tag, service, web title)")
	}
	return f
}

func (f hostFilterFlags) filter() client.HostFilter {
	return client.HostFilter{
		Q:       *f.query,
		Tag:     *f.tag,
		Status:  *f.status,
		Port:    *f.port,
		Service: *f.service,
		Owner:   *f.owner,
	}
}

func RunHosts(args []string) error { return RunHostsW(args, os.Stdout) }

func RunHostsW(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("hosts", flag.ContinueOnError)
	f := addClientFlags(fs)
	hf := addHostFilterFlags(fs, true)
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError("unexpected arguments: %v", fs.Args())
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	hosts, err := c.ListHosts(context.Background(), hf.filter())
	if err != nil {
		return err
	}
	if f.jsonOut() {
		return printJSON(w, hosts)
	}
	rows := make([][]string, 0, len(hosts))
	for _, h := range hosts {
		name := ""
		if len(h.Hostnames) > 0 {
			name = h.Hostnames[0].Name
			for _, n := range h.Hostnames[1:] {
				name += ", " + n.Name
			}
		}
		var tags string
		if len(h.Tags) > 0 {
			sorted := append([]string(nil), h.Tags...)
			sort.Strings(sorted)
			tags = strings.Join(sorted, ", ")
		}
		rows = append(rows, []string{
			h.IP, name, h.OS, h.Status, h.Zone, h.Owner, fmt.Sprint(h.Services), tags,
		})
	}
	table(w, []string{"IP", "HOSTNAME", "OS", "STATUS", "ZONE", "OWNER", "SVC", "TAGS"}, rows)
	fmt.Fprintf(w, "%d host(s)\n", len(hosts))
	return nil
}
