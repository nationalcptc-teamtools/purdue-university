package web

import (
	"net/http"
	"strings"

	"corkboard/internal/model"
	"corkboard/internal/store"
)

type credRow struct {
	model.Cred
	ValidOn int
	AdminOn int
}

type credsData struct {
	baseData
	View   string
	Rows   []credRow
	Matrix store.CredMatrix

	CellLevel func(credID, hostID int64) string
	Notice    string
	Forms     credsForms
	HostIPs   []string
}

type credsForms struct {
	Cred      credForm
	CredErr   string
	Access    accessForm
	AccessErr string
}

func (w *Web) handleCreds(wr http.ResponseWriter, r *http.Request) {
	w.renderCreds(wr, r, http.StatusOK, credsForms{})
}

func (w *Web) renderCreds(wr http.ResponseWriter, r *http.Request, code int, forms credsForms) {
	view := r.URL.Query().Get("view")
	if view != "matrix" {
		view = "table"
	}
	d := credsData{baseData: w.pageData(r, "creds"), View: view}

	creds, err := w.st.ListCreds(r.Context())
	if err != nil {
		http.Error(wr, err.Error(), 500)
		return
	}
	if view == "table" {
		d.Rows = make([]credRow, 0, len(creds))
		for _, c := range creds {
			row := credRow{Cred: c}
			for _, a := range c.Access {
				if a.Level == "admin" {
					row.AdminOn++
				} else if a.Level == "valid" {
					row.ValidOn++
				}
			}
			d.Rows = append(d.Rows, row)
		}
	} else {
		m, err := w.st.CredMatrix(r.Context())
		if err != nil {
			http.Error(wr, err.Error(), 500)
			return
		}
		d.Matrix = m
		d.CellLevel = func(credID, hostID int64) string {
			if cells, ok := m.Cells[credID]; ok {
				return cells[hostID]
			}
			return ""
		}
	}
	if view == "matrix" {

		d.Rows = make([]credRow, 0, len(creds))
		for _, c := range creds {
			d.Rows = append(d.Rows, credRow{Cred: c})
		}
	}
	d.Forms = forms
	if forms.CredErr == "" && forms.AccessErr == "" {
		d.Notice = noticeFrom(r)
	}
	d.HostIPs = w.knownIPs(r.Context())
	wr.Header().Set("Content-Type", "text/html; charset=utf-8")
	wr.WriteHeader(code)
	if err := w.render(wr, r, "creds", d); err != nil {
		w.log.Error("render creds", "err", err)
	}
}

func q(s string) string {
	if s == "" || strings.ContainsAny(s, " \t\"'\\$`&|<>()*?[]#~") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}
