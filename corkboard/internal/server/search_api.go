package server

import (
	"corkboard/internal/store"
	"net/http"
	"strconv"
)

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	page, err := s.store.Search(r.Context(), store.SearchOptions{Query: q.Get("q"), Kind: q.Get("kind"), Cursor: q.Get("cursor"), Limit: limit})
	if err != nil {
		writeErr(w, 400, "invalid_search", err.Error())
		return
	}
	writeJSON(w, 200, page)
}
