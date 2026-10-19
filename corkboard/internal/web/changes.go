package web

import (
	"net/http"
	"strconv"
	"time"

	"corkboard/internal/store"
)

func (w *Web) handleChanges(wr http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := struct {
		baseData
		Since   string
		All     bool
		Standup bool
		Digest  store.Digest
	}{baseData: w.pageData(r, "changes"), Since: q.Get("since"), All: q.Get("all") == "1"}
	o := store.DigestOptions{User: w.User(r), IncludeOwn: d.All}
	if d.Since != "" {
		ms, err := store.ParseSince(d.Since, time.Now())
		if err != nil {
			d.Err = err.Error()
		}
		o.SinceMS = ms
		d.Standup = true
	}
	if d.Err == "" {
		dg, err := w.st.Digest(r.Context(), o)
		if err != nil {
			http.Error(wr, err.Error(), 500)
			return
		}
		d.Digest = dg
	}
	if err := w.render(wr, r, "changes", d); err != nil {
		w.log.Error("render changes", "err", err)
	}
}

func (w *Web) handleChangesAck(wr http.ResponseWriter, r *http.Request) {
	if !w.checkCSRF(wr, r) {
		http.Error(wr, "invalid CSRF token", 403)
		return
	}
	through, err := strconv.ParseInt(r.FormValue("through"), 10, 64)
	if err != nil || through < 0 {
		http.Error(wr, "invalid event ID", 400)
		return
	}
	if _, err = w.st.AckDigest(r.Context(), w.User(r), through); err != nil {
		http.Error(wr, err.Error(), 500)
		return
	}
	http.Redirect(wr, r, "/changes", 303)
}
