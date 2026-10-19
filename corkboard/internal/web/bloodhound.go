package web

import (
	"fmt"
	"net/http"

	"corkboard/internal/bloodhound"
	"corkboard/internal/config"
)

type bloodhoundData struct {
	baseData
	BH     bloodhound.Status
	Notice string
}

func (w *Web) bloodhoundService() *bloodhound.Service {

	if w.bh != nil {
		return w.bh
	}
	return bloodhound.New(w.st, config.BloodHound{})
}

func (w *Web) renderBloodHound(wr http.ResponseWriter, r *http.Request, notice string, actionErr error) {
	st, err := w.bloodhoundService().Status(r.Context())
	if err != nil {
		http.Error(wr, "could not read BloodHound status", 500)
		return
	}
	d := bloodhoundData{baseData: w.pageData(r, "bloodhound"), BH: st, Notice: notice}
	if actionErr != nil {
		d.Err = actionErr.Error()
		d.Notice = ""
	}
	if partial(r) {
		wr.Header().Set("HX-Retarget", "main")
		wr.Header().Set("HX-Reselect", "main")
		wr.Header().Set("HX-Reswap", "outerHTML")
	}
	if err := w.render(wr, r, "bloodhound", d); err != nil {
		w.log.Error("render BloodHound", "err", err)
	}
}

func (w *Web) handleBloodHound(wr http.ResponseWriter, r *http.Request) {
	w.renderBloodHound(wr, r, "", nil)
}

func (w *Web) handleBloodHoundCheck(wr http.ResponseWriter, r *http.Request) {
	if !w.checkCSRF(wr, r) {
		http.Error(wr, "csrf", 403)
		return
	}
	info, err := w.bloodhoundService().Check(r.Context())
	w.renderBloodHound(wr, r, fmt.Sprintf("Connected to BloodHound %s (%s).", info.Version, info.Mode), err)
}

func (w *Web) handleBloodHoundSync(wr http.ResponseWriter, r *http.Request) {
	if !w.checkCSRF(wr, r) {
		http.Error(wr, "csrf", 403)
		return
	}
	err := w.bloodhoundService().RequestSync(r.Context())
	w.renderBloodHound(wr, r, "Ownership sync queued. Results will appear below.", err)
}

func (w *Web) handleBloodHoundTarget(wr http.ResponseWriter, r *http.Request) {
	if !w.checkCSRF(wr, r) {
		http.Error(wr, "csrf", 403)
		return
	}
	kind, identity, ip := r.FormValue("kind"), r.FormValue("identity"), r.FormValue("ip")
	var hostID *int64
	if kind == "Computer" {
		h, err := w.st.GetHost(r.Context(), ip)
		if err != nil {
			w.renderBloodHound(wr, r, "", fmt.Errorf("Computer requires an existing compromised host IP"))
			return
		}
		hostID = &h.Host.ID
	} else if ip != "" {
		w.renderBloodHound(wr, r, "", fmt.Errorf("IP is only used for Computer mappings"))
		return
	}
	_, err := w.st.SaveBloodHoundTarget(r.Context(), w.User(r), kind, identity, hostID)
	if err == nil {
		w.bloodhoundService().WakeAuto()
	}
	w.renderBloodHound(wr, r, "Owned identity recorded. Check its sync status below, or download the identity export.", err)
}

func (w *Web) handleBloodHoundExport(wr http.ResponseWriter, r *http.Request) {
	body, err := w.bloodhoundService().ExportOwned(r.Context())
	if err != nil {
		http.Error(wr, "could not export owned identities", 500)
		return
	}
	wr.Header().Set("Content-Type", "text/plain; charset=utf-8")
	wr.Header().Set("Content-Disposition", `attachment; filename="bloodhound-owned.txt"`)
	fmt.Fprint(wr, body)
}
