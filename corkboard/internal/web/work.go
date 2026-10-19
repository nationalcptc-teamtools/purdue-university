package web

import (
	"fmt"
	"net/http"
	"net/url"

	"corkboard/internal/store"
)

func (w *Web) handleWork(wr http.ResponseWriter, r *http.Request) {
	ref, err := store.ParseTarget(r.URL.Query().Get("target"))
	if err != nil {
		http.Error(wr, err.Error(), http.StatusBadRequest)
		return
	}
	t, err := w.st.ResolveTarget(r.Context(), ref)
	if err != nil || t.HostID == nil {
		http.Redirect(wr, r, "/hosts", http.StatusSeeOther)
		return
	}
	d, err := w.st.GetHostByID(r.Context(), *t.HostID)
	if err != nil {
		http.Redirect(wr, r, "/hosts", http.StatusSeeOther)
		return
	}
	anchor := ""
	switch ref.Kind {
	case "service":
		anchor = fmt.Sprintf("#svc-%d", ref.ID)
	case "task":
		anchor = "#tasks"
	}
	http.Redirect(wr, r, "/hosts/"+url.PathEscape(d.Host.IP)+anchor, http.StatusSeeOther)
}
