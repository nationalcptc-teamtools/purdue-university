package web

import (
	"bytes"
	"io/fs"
	"net/http"
	"time"
)

var assetCache = map[string]asset{}

type asset struct {
	body    []byte
	modTime time.Time
}

func (w *Web) handleAssets(wr http.ResponseWriter, r *http.Request) {
	name := r.URL.Path[len("/assets/"):]
	if name == "" || name == "/" || len(name) > 200 ||
		anyOf(name, "..", "\\", "\x00") {
		http.NotFound(wr, r)
		return
	}
	a, ok := assetCache[name]
	if !ok {
		b, err := fs.ReadFile(assetsFS, "assets/"+name)
		if err != nil {
			http.NotFound(wr, r)
			return
		}
		a = asset{body: b}
		assetCache[name] = a
	}
	var ct string
	switch {
	case len(name) > 3 && name[len(name)-3:] == ".js":
		ct = "text/javascript; charset=utf-8"
	case len(name) > 4 && name[len(name)-4:] == ".css":
		ct = "text/css; charset=utf-8"
	default:
		ct = "application/octet-stream"
	}
	wr.Header().Set("Content-Type", ct)
	wr.Header().Set("Cache-Control", "max-age=300")
	http.ServeContent(wr, r, name, a.modTime, bytes.NewReader(a.body))
}

func anyOf(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}
