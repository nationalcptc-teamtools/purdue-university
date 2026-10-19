package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"corkboard/internal/store"
)

func (w *Web) webAction(h func(wr http.ResponseWriter, r *http.Request, user string) error) http.HandlerFunc {
	return w.requireWeb(func(wr http.ResponseWriter, r *http.Request) {
		if !w.checkCSRF(wr, r) {
			http.Error(wr, "csrf check failed", http.StatusForbidden)
			return
		}
		user := w.User(r)
		if err := h(wr, r, user); err != nil {
			if partial(r) {

				http.Error(wr, err.Error(), http.StatusUnprocessableEntity)
				return
			}
			w.log.Error("web action", "err", err)
			hxRedirectBack(wr, r, "/")
			return
		}
	})
}

func actionPage(r *http.Request, fallback string) string {
	for _, value := range []string{r.Header.Get("HX-Current-URL"), r.Referer()} {
		u, err := url.Parse(value)
		if err != nil || value == "" || u.User != nil || (u.Host != "" && !strings.EqualFold(u.Host, r.Host)) || (u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		if u.Path == "/" || u.Path == "/tasks" || u.Path == "/hosts" || strings.HasPrefix(u.Path, "/hosts/") {
			return u.EscapedPath() + querySuffix(u.RawQuery)
		}
	}
	return fallback
}

func querySuffix(query string) string {
	if query == "" {
		return ""
	}
	return "?" + query
}

func (w *Web) renderPage(wr http.ResponseWriter, r *http.Request, fallback string) error {
	pr, err := http.NewRequest("GET", actionPage(r, fallback), nil)
	if err != nil {
		return err
	}
	pr = pr.WithContext(r.Context())
	if c := r.Header.Get("Cookie"); c != "" {
		pr.Header.Set("Cookie", c)
	}
	if partial(r) {
		pr.Header.Set("HX-Request", "true")
		wr.Header().Set("HX-Retarget", "main")
		wr.Header().Set("HX-Reselect", "main")
		wr.Header().Set("HX-Reswap", "outerHTML")
	}
	w.Handler().ServeHTTP(wr, pr)
	return nil
}

func (w *Web) hostActionClaim(wr http.ResponseWriter, r *http.Request, user string) error {
	ip := r.PathValue("ip")
	steal := r.FormValue("steal") == "true"
	if err := w.st.ClaimHost(r.Context(), ip, user, steal); err != nil {
		return err
	}
	return w.renderPage(wr, r, "/hosts/"+ip)
}

func (w *Web) hostActionRelease(wr http.ResponseWriter, r *http.Request, user string) error {
	ip := r.PathValue("ip")
	if err := w.st.ReleaseHost(r.Context(), ip, user); err != nil {
		return err
	}
	return w.renderPage(wr, r, "/hosts/"+ip)
}

func (w *Web) hostActionPriority(wr http.ResponseWriter, r *http.Request, user string) error {
	ip := r.PathValue("ip")
	p, err := strconv.Atoi(r.FormValue("priority"))
	if err != nil {
		return fmt.Errorf("priority must be 1, 2, or 3")
	}
	if err := w.st.SetPriority(r.Context(), ip, user, p); err != nil {
		return err
	}
	return w.renderPage(wr, r, "/hosts/"+ip)
}

func (w *Web) serviceActionExplored(wr http.ResponseWriter, r *http.Request, user string) error {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return err
	}
	if err := w.st.SetServiceExplored(r.Context(), user, id, r.FormValue("explored") == "1"); err != nil {
		return err
	}
	return w.renderPage(wr, r, "/hosts/"+r.PathValue("ip"))
}

func (w *Web) serviceActionClaim(wr http.ResponseWriter, r *http.Request, user string) error {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return err
	}
	ref := store.TargetRef{Kind: "service", ID: id}
	switch r.FormValue("action") {
	case "release":
		err = w.st.ReleaseTarget(r.Context(), user, ref)
	default:
		_, err = w.st.ClaimTarget(r.Context(), user, ref, r.FormValue("action") == "steal")
	}
	if err != nil {
		return err
	}
	return w.renderPage(wr, r, "/hosts/"+r.PathValue("ip"))
}

func (w *Web) hostActionStatus(wr http.ResponseWriter, r *http.Request, user string) error {
	ip := r.PathValue("ip")
	status := r.FormValue("status")
	reason := r.FormValue("reason")
	if status == "" {
		return nil
	}
	if err := w.st.SetStatus(r.Context(), ip, user, status, reason); err != nil {
		return err
	}
	return w.renderPage(wr, r, "/hosts/"+ip)
}

func (w *Web) hostActionNote(wr http.ResponseWriter, r *http.Request, user string) error {
	ip := r.PathValue("ip")
	in := store.LogInput{
		Body:    strings.TrimSpace(r.FormValue("body")),
		Outcome: r.FormValue("outcome"),
		Command: strings.TrimSpace(r.FormValue("command")),
		Output:  strings.TrimRight(r.FormValue("output"), " \t\r\n"),
	}
	if in.Body == "" {
		return nil
	}
	if v := r.FormValue("service"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("bad service id %q", v)
		}
		in.ServiceID = &id
	}
	if err := w.st.AddLog(r.Context(), ip, user, in); err != nil {
		return err
	}
	return w.renderPage(wr, r, "/hosts/"+ip)
}

func (w *Web) hostActionTags(wr http.ResponseWriter, r *http.Request, user string) error {
	ip := r.PathValue("ip")
	add := r.FormValue("add")
	remove := r.FormValue("remove")
	if add == "" && remove == "" {
		return nil
	}
	var addList, removeList []string
	if add != "" {
		addList = []string{add}
	}
	if remove != "" {
		removeList = []string{remove}
	}
	if err := w.st.SetTags(r.Context(), ip, user, addList, removeList); err != nil {
		return err
	}
	return w.renderPage(wr, r, "/hosts/"+ip)
}

func (w *Web) hostActionOwned(wr http.ResponseWriter, r *http.Request, user string) error {
	ip := r.PathValue("ip")
	level := r.FormValue("level")
	viaText := r.FormValue("via_text")
	var viaFinding, viaCred *int64
	if v := r.FormValue("via_finding"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			viaFinding = &n
		}
	}
	if v := r.FormValue("via_cred"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			viaCred = &n
		}
	}
	if err := w.st.SetCompromise(r.Context(), ip, user, level, viaFinding, viaCred, viaText); err != nil {
		return err
	}
	return w.renderPage(wr, r, "/hosts/"+ip)
}

func taskID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func (w *Web) taskActionClaim(wr http.ResponseWriter, r *http.Request, user string) error {
	id, err := taskID(r)
	if err != nil {
		return err
	}
	steal := r.FormValue("steal") == "true"
	if err := w.st.ClaimTask(r.Context(), id, user, steal); err != nil {
		return err
	}
	return w.renderTasksPage(wr, r)
}

func (w *Web) taskActionRelease(wr http.ResponseWriter, r *http.Request, user string) error {
	id, err := taskID(r)
	if err != nil {
		return err
	}
	if err := w.st.ReleaseTask(r.Context(), id, user); err != nil {
		return err
	}
	return w.renderTasksPage(wr, r)
}

func (w *Web) taskActionDone(wr http.ResponseWriter, r *http.Request, user string) error {
	id, err := taskID(r)
	if err != nil {
		return err
	}
	if err := w.st.SetTaskState(r.Context(), id, user, "done", r.FormValue("note")); err != nil {
		return err
	}
	return w.renderTasksPage(wr, r)
}

func (w *Web) taskActionBlock(wr http.ResponseWriter, r *http.Request, user string) error {
	id, err := taskID(r)
	if err != nil {
		return err
	}
	if err := w.st.SetTaskState(r.Context(), id, user, "blocked", r.FormValue("note")); err != nil {
		return err
	}
	return w.renderTasksPage(wr, r)
}

func (w *Web) renderTasksPage(wr http.ResponseWriter, r *http.Request) error {
	return w.renderPage(wr, r, "/tasks")
}

func (w *Web) alarmAck(wr http.ResponseWriter, r *http.Request, user string) error {
	max, err := w.st.MaxEventID(r.Context())
	if err != nil {
		return err
	}
	if err := w.st.SetMeta(r.Context(), "scope_alarm_ack", strconv.FormatInt(max, 10)); err != nil {
		return err
	}
	_ = user
	return w.renderPage(wr, r, "/")
}

var _ = store.ErrNotOwner
