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
	"time"
)

func RunChecks(args []string) error { return RunChecksW(args, os.Stdout) }
func RunChecksW(args []string, w io.Writer) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	sub := args[0]
	fs := flag.NewFlagSet("checks "+sub, flag.ContinueOnError)
	f := addClientFlags(fs)
	cred := fs.Int64("cred", 0, "credential ID")
	endpoint := fs.Int64("endpoint", 0, "authentication endpoint ID")
	generation := fs.Int64("generation", 0, "endpoint generation from queue")
	target := fs.String("target", "", "host/service/application reference")
	vantage := fs.String("vantage", "*", "source vantage (* all; empty unknown)")
	state := fs.String("state", "", "queue state")
	limit := fs.Int("limit", 50, "page size")
	offset := fs.Int("offset", 0, "page offset")
	reason := fs.String("reason", "", "reason/detail")
	owner := fs.String("expected-owner", "", "owner for explicit takeover")
	result := fs.String("result", "", "invalid|valid|admin|inconclusive")
	occurred := fs.String("occurred-at", "", "RFC3339 occurrence time")
	loss := fs.Bool("confirmed-loss", false, "confirm invalid revalidation ended authentication access")
	scope := fs.String("scope", "unknown", "unknown|domain|local|target|all")
	value := fs.String("value", "", "scope value")
	protocols := fs.String("protocols", "", "space-separated protocol restrictions")
	revision := fs.Int64("revision-of", 0, "previous credential revision")
	cracked := fs.Int64("cracked-from", 0, "uncracked-hash credential ID")
	decision := fs.String("decision", "eligible", "eligible|excluded")
	observation := fs.Int64("observation", 0, "historical observation ID")
	if err := fs.Parse(reorderArgs(fs, args[1:])); err != nil {
		return err
	}
	c, err := f.buildClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	var out any
	key := store.CheckKey{CredID: *cred, EndpointID: *endpoint, Generation: *generation}
	switch sub {
	case "list":
		q := url.Values{"cred_id": {strconv.FormatInt(*cred, 10)}, "target": {*target}, "vantage": {*vantage}, "state": {*state}, "limit": {strconv.Itoa(*limit)}, "offset": {strconv.Itoa(*offset)}}
		err = c.Workflow(ctx, "GET", "/api/v1/checks?"+q.Encode(), nil, &out)
	case "profiles":
		err = c.Workflow(ctx, "GET", "/api/v1/credential-profiles", nil, &out)
	case "history":
		err = c.Workflow(ctx, "GET", fmt.Sprintf("/api/v1/checks/history?cred_id=%d&endpoint_id=%d", *cred, *endpoint), nil, &out)
	case "observations":
		err = c.Workflow(ctx, "GET", fmt.Sprintf("/api/v1/access-observations?cred_id=%d", *cred), nil, &out)
	case "scope", "retire", "activate":
		var profiles []store.CredentialProfile
		if err = c.Workflow(ctx, "GET", "/api/v1/credential-profiles", nil, &profiles); err != nil {
			return err
		}
		var p *store.CredentialProfile
		for i := range profiles {
			if profiles[i].CredID == *cred {
				p = &profiles[i]
				break
			}
		}
		if p == nil {
			return usageError("unknown credential")
		}
		if sub == "scope" {
			p.ScopeKind = *scope
			p.ScopeValue = *value
			p.Protocols = strings.Fields(*protocols)
			if *revision > 0 {
				p.RevisionOf = revision
			}
			if *cracked > 0 {
				p.CrackedFrom = cracked
			}
		} else {
			p.Retired = sub == "retire"
		}
		err = c.Workflow(ctx, "POST", "/api/v1/credential-profiles", p, &out)
	case "applicability":
		err = c.Workflow(ctx, "POST", "/api/v1/checks/applicability", map[string]any{"cred_id": *cred, "endpoint_id": *endpoint, "decision": *decision, "reason": *reason}, &out)
	case "associate":
		err = c.Workflow(ctx, "POST", "/api/v1/access-observations", map[string]any{"id": *observation, "endpoint_id": *endpoint, "reason": *reason}, &out)
	case "result":
		in := store.CheckResultInput{CheckKey: key, Result: *result, Detail: *reason, ConfirmedLoss: *loss}
		if *occurred != "" {
			at, e := time.Parse(time.RFC3339, *occurred)
			if e != nil {
				return e
			}
			n := at.UnixMilli()
			in.OccurredAt = &n
		}
		err = c.Workflow(ctx, "POST", "/api/v1/checks/result", in, &out)
	case "claim", "release", "block", "recheck", "waive":
		keys := []store.CheckKey{key}
		if fs.NArg() > 0 {
			keys = nil
			for _, text := range fs.Args() {
				parts := strings.Split(text, ":")
				if len(parts) != 3 {
					return usageError("bulk checks use CRED:ENDPOINT:GENERATION")
				}
				values := make([]int64, 3)
				for i, v := range parts {
					values[i], err = strconv.ParseInt(v, 10, 64)
					if err != nil || values[i] <= 0 {
						return usageError("invalid check key")
					}
				}
				keys = append(keys, store.CheckKey{CredID: values[0], EndpointID: values[1], Generation: values[2]})
			}
		}
		err = c.Workflow(ctx, "POST", "/api/v1/checks/action", store.CheckAction{Keys: keys, Action: sub, Reason: *reason, ExpectedOwner: *owner}, &out)
	default:
		return usageError("checks action must be list, profiles, scope, retire, activate, claim, release, block, recheck, waive, result, history, applicability, observations, or associate")
	}
	if err != nil {
		return err
	}
	return printJSON(w, out)
}
