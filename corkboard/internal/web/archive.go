package web

import "net/http"

func (w *Web) handleArchive(wr http.ResponseWriter, r *http.Request) {
	wr.Header().Set("Cache-Control", "no-store")
	if err := w.render(wr, r, "archive", w.pageData(r, "archive")); err != nil {
		http.Error(wr, "archive page failed", 500)
	}
}
func (w *Web) handleArchiveExport(wr http.ResponseWriter, r *http.Request) {
	if !w.checkCSRF(wr, r) {
		http.Error(wr, "invalid CSRF token", 403)
		return
	}
	if w.archiveExport == nil {
		http.Error(wr, "archive export unavailable", 503)
		return
	}
	w.archiveExport(wr, r)
}
func (w *Web) handleArchiveInspect(wr http.ResponseWriter, r *http.Request) {

	if r.Header.Get("X-CSRF-Token") == "" {
		r.Header.Set("X-CSRF-Token", r.URL.Query().Get("csrf"))
	}
	if r.Header.Get("X-CSRF-Token") == "" || !w.checkCSRF(wr, r) {
		http.Error(wr, "invalid CSRF token", 403)
		return
	}
	if w.archiveInspect == nil {
		http.Error(wr, "archive inspection unavailable", 503)
		return
	}
	w.archiveInspect(wr, r)
}
