package web

import (
	"corkboard/internal/store"
	"net/http"
	"net/url"
)

func (w *Web) handleSearch(wr http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	d := struct {
		baseData
		Q, Kind, Next string
		Results       []store.SearchHit
	}{baseData: w.pageData(r, "search"), Q: query.Get("q"), Kind: query.Get("kind")}
	if d.Q != "" {
		page, err := w.st.Search(r.Context(), store.SearchOptions{Query: d.Q, Kind: d.Kind, Cursor: query.Get("cursor"), Limit: 50})
		if err != nil {
			d.Err = err.Error()
		} else {
			d.Results = page.Results
			if page.NextCursor != "" {
				next := url.Values{"q": {d.Q}, "kind": {d.Kind}, "cursor": {page.NextCursor}}
				d.Next = "/search?" + next.Encode()
			}
		}
	}
	if err := w.render(wr, r, "search", d); err != nil {
		w.log.Error("render search", "err", err)
	}
}
