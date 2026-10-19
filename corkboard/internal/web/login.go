package web

import (
	"net/http"
	"time"

	"corkboard/internal/auth"
)

func (w *Web) handleLoginGET(wr http.ResponseWriter, r *http.Request) {
	if _, ok := w.sessionFromCookie(r); ok {
		http.Redirect(wr, r, "/", http.StatusSeeOther)
		return
	}
	if err := w.render(wr, r, "login", baseData{
		Engage: w.engage,
		Page:   "login",
		Now:    time.Now(),
	}); err != nil {
		w.log.Error("render login", "err", err)
	}
}

func (w *Web) checkPassphrase(r *http.Request, p string) bool {
	if w.passOK == nil {
		return false
	}
	if w.limiter == nil {
		return w.passOK(p)
	}
	now := time.Now()
	ip := auth.RemoteIP(r.RemoteAddr)
	if w.limiter.Blocked(ip, now) {
		return false
	}
	if !w.passOK(p) {
		w.limiter.Record(ip, now)
		return false
	}
	return true
}

func (w *Web) handleLoginPOST(wr http.ResponseWriter, r *http.Request) {
	if w.limiter != nil && w.limiter.Blocked(auth.RemoteIP(r.RemoteAddr), time.Now()) {
		w.log.Info("login rate limited", "ip", auth.RemoteIP(r.RemoteAddr))
		http.Error(wr, "Too many wrong passphrases. Wait a few minutes and try again.", http.StatusTooManyRequests)
		return
	}
	pass := r.FormValue("passphrase")
	user := r.FormValue("user")
	if _, ok := w.sessionFromCookie(r); ok {
		if !w.checkPassphrase(r, pass) {
			http.Error(wr, "wrong passphrase", http.StatusUnauthorized)
			return
		}

		if u, _ := w.sessionFromCookie(r); validUserName(u) {
			w.loginUser(wr, u)
		}
		http.Redirect(wr, r, "/", http.StatusSeeOther)
		return
	}

	if !w.checkPassphrase(r, pass) {
		w.renderLoginErr(wr, r, http.StatusUnauthorized, user, "That passphrase is wrong.")
		return
	}
	if !validUserName(user) {
		w.renderLoginErr(wr, r, http.StatusBadRequest, user, "Display names use letters, digits, _ . - (up to 32).")
		return
	}
	w.loginUser(wr, user)
	http.Redirect(wr, r, "/", http.StatusSeeOther)
}

func (w *Web) renderLoginErr(wr http.ResponseWriter, r *http.Request, code int, user, msg string) {
	wr.WriteHeader(code)
	if err := w.render(wr, r, "login", baseData{
		Engage: w.engage,
		Page:   "login",
		Now:    time.Now(),
		User:   user,
		Err:    msg,
	}); err != nil {
		w.log.Error("render login", "err", err)
	}
}

func (w *Web) handleLogout(wr http.ResponseWriter, r *http.Request) {
	if !w.checkCSRF(wr, r) {
		http.Error(wr, "csrf", http.StatusForbidden)
		return
	}
	setCookie(wr, sessionCookie, "", -1, true)
	setCookie(wr, csrfCookie, "", -1, true)
	setCookie(wr, lastSeenCookie, "", -1, false)
	http.Redirect(wr, r, "/login", http.StatusSeeOther)
}
