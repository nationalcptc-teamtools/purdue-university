package web

import (
	"corkboard/internal/model"
	"corkboard/internal/store"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func (w *Web) handleFindingNew(wr http.ResponseWriter, r *http.Request) {
	w.renderFindingForm(wr, r, nil, "")
}
func (w *Web) renderFindingForm(wr http.ResponseWriter, r *http.Request, d *store.FindingDetail, message string) {
	type option struct{ Value, Label string }
	var options []option
	hosts, err := w.st.ListExportHosts(r.Context())
	if err != nil {
		http.Error(wr, "could not list affected hosts", 500)
		return
	}
	for _, h := range hosts {
		options = append(options, option{fmt.Sprintf("host:%d", h.ID), h.IP})
	}
	apps, err := w.st.Applications(r.Context())
	if err != nil {
		http.Error(wr, "could not list applications", 500)
		return
	}
	for _, app := range apps {
		options = append(options, option{fmt.Sprintf("application:%d", app.ID), app.Origin + " " + app.Realm})
	}
	selected := r.URL.Query().Get("target")
	if ref, err := store.ParseTarget(selected); err == nil && ref.Kind == "service" {
		target, err := w.st.ResolveTarget(r.Context(), ref)
		if err == nil {
			options = append(options, option{selected, target.Label})
		}
	}

	var extra []model.FindingHost
	if d != nil {
		covered := map[int64]bool{}
		for _, a := range d.Assets {
			if a.HostID != nil {
				covered[*a.HostID] = true
			}
		}
		for _, h := range d.Hosts {
			if !covered[h.HostID] {
				extra = append(extra, h)
			}
		}
	}
	data := struct {
		baseData
		D          *store.FindingDetail
		Target     string
		Options    []option
		ExtraHosts []model.FindingHost
	}{w.pageData(r, "findings"), d, selected, options, extra}
	data.Err = message
	if err := w.render(wr, r, "findingDetail", data); err != nil {
		http.Error(wr, "finding page failed", 500)
	}
}
func (w *Web) handleFindingDetail(wr http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := w.st.FindingDetail(r.Context(), id)
	if err != nil {
		http.Error(wr, "finding not found", 404)
		return
	}
	w.renderFindingForm(wr, r, d, "")
}
func findingForm(r *http.Request) (store.FindingInput, error) {
	in := store.FindingInput{Title: r.FormValue("title"), Severity: r.FormValue("severity"), Description: r.FormValue("description"), Evidence: r.FormValue("evidence"), State: r.FormValue("state"), Reason: r.FormValue("reason"), ReportRef: r.FormValue("report_ref")}
	for _, v := range strings.Fields(strings.Join(r.Form["targets"], " ")) {
		t, err := store.ParseTarget(v)
		if err != nil {
			return in, err
		}
		in.Targets = append(in.Targets, t)
	}
	for _, v := range strings.Fields(strings.Join(r.Form["remove_targets"], " ")) {
		t, err := store.ParseTarget(v)
		if err != nil {
			return in, err
		}
		in.RemoveTargets = append(in.RemoveTargets, t)
	}
	if r.FormValue("merge_into") != "" {
		id, err := strconv.ParseInt(r.FormValue("merge_into"), 10, 64)
		if err != nil || id <= 0 {
			return in, fmt.Errorf("invalid merge destination")
		}
		in.MergeInto = id
	}
	return in, nil
}
func (w *Web) handleFindingCreate(wr http.ResponseWriter, r *http.Request) {
	if !w.checkCSRF(wr, r) {
		http.Error(wr, "invalid CSRF token", 403)
		return
	}
	in, err := findingForm(r)
	if err != nil {
		http.Error(wr, err.Error(), 400)
		return
	}
	id, err := w.st.CreateFinding(r.Context(), w.User(r), in)
	if err != nil {
		w.renderFindingForm(wr, r, nil, err.Error())
		return
	}
	http.Redirect(wr, r, fmt.Sprintf("/findings/%d", id), 303)
}
func (w *Web) handleFindingEdit(wr http.ResponseWriter, r *http.Request) {
	if !w.checkCSRF(wr, r) {
		http.Error(wr, "invalid CSRF token", 403)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	in, err := findingForm(r)
	if err == nil {

		if cur, e := w.st.FindingDetail(r.Context(), id); e == nil && in.State == cur.State {
			in.State = ""
		}
		err = w.st.EditFinding(r.Context(), w.User(r), id, in)
	}
	if err != nil {
		d, _ := w.st.FindingDetail(r.Context(), id)
		w.renderFindingForm(wr, r, d, err.Error())
		return
	}
	http.Redirect(wr, r, fmt.Sprintf("/findings/%d", id), 303)
}
func (w *Web) handleEvidenceUpload(wr http.ResponseWriter, r *http.Request) {
	if !w.checkCSRF(wr, r) {
		http.Error(wr, "invalid CSRF token", 403)
		return
	}
	if w.evidenceUpload == nil {
		http.Error(wr, "evidence upload unavailable", 503)
		return
	}
	w.evidenceUpload(wr, r)
}
func (w *Web) handleEvidenceRead(wr http.ResponseWriter, r *http.Request) {
	if w.evidenceRead == nil {
		http.Error(wr, "evidence unavailable", 503)
		return
	}
	w.evidenceRead(wr, r)
}
