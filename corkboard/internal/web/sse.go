package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"corkboard/internal/model"
)

const sseHeartbeat = 20 * time.Second

func (w *Web) handleEvents(wr http.ResponseWriter, r *http.Request) {
	if _, ok := w.sessionFromCookie(r); !ok {
		if !w.bearerOK(r) {
			http.Error(wr, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	lastID := int64(0)
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		var err error
		lastID, err = parseID(v)
		if err != nil {
			http.Error(wr, "bad Last-Event-ID", http.StatusBadRequest)
			return
		}
	}

	ch, cancel := w.broker.Subscribe()
	defer cancel()
	var fl http.Flusher
	if f, ok := wr.(http.Flusher); ok {
		fl = f
	}
	flush := func() {
		if fl != nil {
			fl.Flush()
		}
	}
	wr.Header().Set("Content-Type", "text/event-stream")
	wr.Header().Set("Cache-Control", "no-cache")
	wr.Header().Set("Connection", "keep-alive")
	wr.Header().Set("X-Accel-Buffering", "no")

	fmt.Fprint(wr, ": cork\n\n")
	flush()

	for {
		rows, err := w.st.EventsAfter(r.Context(), lastID, 500)
		if err != nil {
			return
		}
		for _, e := range rows {
			writeSSE(wr, e)
			lastID = e.ID
		}
		flush()
		if len(rows) < 500 {
			break
		}
	}

	hb := time.NewTicker(sseHeartbeat)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-hb.C:
			fmt.Fprint(wr, ": ping\n\n")
			flush()
		case e, ok := <-ch:
			if !ok {

				return
			}
			if e.ID <= lastID {
				continue
			}
			writeSSE(wr, e)
			lastID = e.ID
			flush()
		}
	}
}

func writeSSE(wr http.ResponseWriter, e model.Event) {
	fmt.Fprintf(wr, "id: %d\n", e.ID)
	fmt.Fprintf(wr, "event: %s\n", e.Kind)
	b, _ := json.Marshal(e)
	fmt.Fprintf(wr, "data: %s\n\n", b)
}

func parseID(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty id")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid id")
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

func (w *Web) bearerOK(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	pass := strings.TrimPrefix(h, "Bearer ")
	return pass != "" && pass != h && w.checkPassphrase(r, pass)
}
