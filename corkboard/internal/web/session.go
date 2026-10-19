package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	sessionCookie  = "cork_session"
	csrfCookie     = "cork_csrf"
	lastSeenCookie = "cork_lastseen"

	sessionTTL   = 12 * time.Hour
	maxCSRFBytes = 64
)

func (w *Web) signSession(user string, exp time.Time) string {
	payload := user + "|" + strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, w.secret)
	mac.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

func (w *Web) sessionFromCookie(r *http.Request) (user string, ok bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	payload, sig := parts[0], parts[1]
	mac := hmac.New(sha256.New, w.secret)
	mac.Write([]byte(payload))
	want := mac.Sum(nil)
	if len(sig) != len(want)*2 || !hmac.Equal([]byte(sig), []byte(hex.EncodeToString(want))) {
		return "", false
	}
	f := strings.SplitN(payload, "|", 2)
	if len(f) != 2 {
		return "", false
	}
	exp, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	if !validUserName(f[0]) {
		return "", false
	}
	return f[0], true
}

func validUserName(u string) bool {
	if u == "" || len(u) > 32 {
		return false
	}
	for _, r := range u {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_', r == '.', r == '-':
		default:
			return false
		}
	}
	return true
}

func (w *Web) loginUser(wr http.ResponseWriter, user string) {
	now := time.Now()
	setCookie(wr, sessionCookie, w.signSession(user, now.Add(sessionTTL)), int(sessionTTL.Seconds()), true)
	csrf := make([]byte, 16)
	if _, err := rand.Read(csrf); err != nil {
		return
	}
	setCookie(wr, csrfCookie, hex.EncodeToString(csrf), int(sessionTTL.Seconds()), true)
}

func setCookie(wr http.ResponseWriter, name, value string, maxAgeSec int, httpOnly bool) {
	http.SetCookie(wr, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAgeSec,
		HttpOnly: httpOnly, SameSite: http.SameSiteStrictMode,
	})
}

func (w *Web) requireWeb(h http.HandlerFunc) http.HandlerFunc {
	return func(wr http.ResponseWriter, r *http.Request) {
		if _, ok := w.sessionFromCookie(r); !ok {
			http.Redirect(wr, r, "/login", http.StatusSeeOther)
			return
		}
		h(wr, r)
	}
}

func (w *Web) User(r *http.Request) string {
	u, _ := w.sessionFromCookie(r)
	return u
}

func (w *Web) checkCSRF(wr http.ResponseWriter, r *http.Request) bool {
	var got string
	if v := r.Header.Get("X-CSRF-Token"); v != "" {
		got = v
	} else if v := r.FormValue("csrf"); v != "" {
		got = v
	}
	c, err := r.Cookie(csrfCookie)
	if err != nil || got == "" || len(got) > maxCSRFBytes ||
		subtle.ConstantTimeCompare([]byte(got), []byte(c.Value)) != 1 {
		return false
	}
	return true
}

func (w *Web) CSRFToken(r *http.Request) string {
	c, err := r.Cookie(csrfCookie)
	if err != nil {
		return ""
	}
	return c.Value
}
