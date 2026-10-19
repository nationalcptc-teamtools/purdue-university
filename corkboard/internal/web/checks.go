package web

import (
	"corkboard/internal/store"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (w *Web) handleChecks(wr http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cred, _ := strconv.ParseInt(q.Get("cred_id"), 10, 64)
	offset, _ := strconv.Atoi(q.Get("offset"))
	f := store.CheckFilter{CredID: cred, Vantage: "*", State: q.Get("state"), Applicability: q.Get("applicability"), Offset: offset, Limit: 50}
	if q.Has("vantage") {
		f.Vantage = q.Get("vantage")
	}
	if q.Get("target") != "" {
		ref, err := store.ParseTarget(q.Get("target"))
		if err != nil {
			http.Error(wr, err.Error(), 400)
			return
		}
		f.Target = &ref
	}
	page, err := w.st.Checks(r.Context(), f)
	if err != nil {
		http.Error(wr, err.Error(), 400)
		return
	}
	profiles, err := w.st.CredentialProfiles(r.Context())
	if err != nil {
		http.Error(wr, err.Error(), 500)
		return
	}
	observations, err := w.st.AccessObservations(r.Context(), cred)
	if err != nil {
		http.Error(wr, err.Error(), 500)
		return
	}
	data := struct {
		baseData
		Checks                                      store.CheckPage
		Profiles                                    []store.CredentialProfile
		Observations                                []map[string]any
		CredID                                      string
		State, Vantage, Applicability, Target, Next string
		History                                     []store.CheckResult
	}{baseData: w.pageData(r, "checks"), Checks: page, Profiles: profiles, Observations: observations, CredID: q.Get("cred_id"), State: f.State, Vantage: f.Vantage, Applicability: f.Applicability, Target: q.Get("target")}
	if endpoint, err := strconv.ParseInt(q.Get("endpoint_id"), 10, 64); err == nil && cred > 0 {
		data.History, err = w.st.CheckHistory(r.Context(), cred, endpoint)
		if err != nil {
			http.Error(wr, err.Error(), 500)
			return
		}
	}
	if page.More {
		next := url.Values{}
		for k, v := range q {
			next[k] = v
		}
		next.Set("offset", strconv.Itoa(offset+50))
		data.Next = "/checks?" + next.Encode()
	}
	if err = w.render(wr, r, "checks", data); err != nil {
		w.log.Error("render checks", "err", err)
	}
}
func parseIntField(r *http.Request, name string) (int64, error) {
	n, err := strconv.ParseInt(r.FormValue(name), 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid %s", name)
	}
	return n, nil
}
func (w *Web) handleChecksPOST(wr http.ResponseWriter, r *http.Request) {
	if !w.checkCSRF(wr, r) {
		http.Error(wr, "invalid CSRF token", 403)
		return
	}
	user := w.User(r)
	action := r.FormValue("action")
	var err error
	switch action {
	case "profile":
		var p store.CredentialProfile
		p.CredID, err = parseIntField(r, "cred_id")
		if err == nil {
			p.ScopeKind = r.FormValue("scope_kind")
			p.ScopeValue = r.FormValue("scope_value")
			p.Protocols = strings.Fields(r.FormValue("protocols"))
			p.Retired = r.FormValue("retired") == "on"
			if v := r.FormValue("revision_of"); v != "" {
				n, e := strconv.ParseInt(v, 10, 64)
				err = e
				p.RevisionOf = &n
			}
			if v := r.FormValue("cracked_from"); v != "" {
				n, e := strconv.ParseInt(v, 10, 64)
				err = e
				p.CrackedFrom = &n
			}
			if err == nil {
				err = w.st.SetCredentialProfile(r.Context(), user, p)
			}
		}
	case "associate":
		var id, endpoint int64
		id, err = parseIntField(r, "observation_id")
		if err == nil {
			endpoint, err = parseIntField(r, "endpoint_id")
		}
		if err == nil {
			err = w.st.AssociateObservation(r.Context(), user, id, endpoint, r.FormValue("reason"))
		}
	default:
		var key store.CheckKey
		key.CredID, err = parseIntField(r, "cred_id")
		if err == nil {
			key.EndpointID, err = parseIntField(r, "endpoint_id")
		}
		if err == nil {
			key.Generation, err = parseIntField(r, "generation")
		}
		if err == nil {
			switch action {
			case "applicability":
				err = w.st.SetCheckApplicability(r.Context(), user, key.CredID, key.EndpointID, r.FormValue("decision"), r.FormValue("reason"))
			case "result":
				in := store.CheckResultInput{CheckKey: key, Result: r.FormValue("result"), Detail: r.FormValue("detail"), ConfirmedLoss: r.FormValue("confirmed_loss") == "on"}
				if v := r.FormValue("occurred_at"); v != "" {
					at, e := time.Parse(time.RFC3339, v)
					err = e
					if e == nil {
						n := at.UnixMilli()
						in.OccurredAt = &n
					}
				}
				if err == nil {
					_, err = w.st.RecordCheck(r.Context(), user, in)
				}
			default:
				err = w.st.CheckAction(r.Context(), user, store.CheckAction{Keys: []store.CheckKey{key}, Action: action, Reason: r.FormValue("reason"), ExpectedOwner: r.FormValue("expected_owner")})
			}
		}
	}
	if err != nil {
		http.Error(wr, err.Error(), 400)
		return
	}
	http.Redirect(wr, r, "/checks", 303)
}
