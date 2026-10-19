package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"corkboard/internal/archive"
	"corkboard/internal/auth"
)

type ctxKey int

const userKey ctxKey = 0

func userFrom(ctx context.Context) string {
	u, _ := ctx.Value(userKey).(string)
	return u
}

func (s *Server) chain(h http.Handler) http.Handler {
	return s.logMiddleware(s.bodyLimit(s.securityHeaders(s.recoverMiddleware(h))))
}

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic", "panic", fmt.Sprintf("%v", rec), "path", r.URL.Path)
				writeErr(w, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.log.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"ms", time.Since(start).Milliseconds(),
			"user", userFrom(r.Context()),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) bodyLimit(next http.Handler) http.Handler {
	limit := int64(s.cfg.MaxUploadMB) << 20
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestLimit := limit
		if r.URL.Path == "/api/v1/archive/inspect" || r.URL.Path == "/archive/inspect" {
			requestLimit = archive.MaxBytes + (1 << 20)
		}
		if requestLimit > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, requestLimit)
		}
		next.ServeHTTP(w, r)
	})
}

var userRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		ip := auth.RemoteIP(r.RemoteAddr)
		if s.fails.Blocked(ip, now) {
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many wrong passphrases; wait a few minutes")
			return
		}
		pass, ok := bearerToken(r)
		if !ok || !s.checkPassphrase(pass) {
			if ok {
				s.fails.Record(ip, now)
			}
			writeErr(w, http.StatusUnauthorized, "unauthorized", "missing or wrong team passphrase")
			return
		}
		user := r.Header.Get("X-Cork-User")
		if !userRe.MatchString(user) {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "missing or invalid X-Cork-User (1-32 chars of [A-Za-z0-9_.-])")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, user)))
	})
}

func bearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(auth) <= len(prefix) {
		return "", false
	}

	if len(auth) < 7 || auth[0]|0x20 != 'b' || auth[1]|0x20 != 'e' || auth[2]|0x20 != 'a' || auth[3]|0x20 != 'r' || auth[4]|0x20 != 'e' || auth[5]|0x20 != 'r' || auth[6] != ' ' {
		return "", false
	}
	return auth[len(prefix):], true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]string{"error": msg, "code": errCode})
}

var (
	errBadJSON      = errors.New("bad json")
	errBodyTooLarge = errors.New("body too large")
)

func isMaxBytes(err error) bool {
	var mb *http.MaxBytesError
	return errors.As(err, &mb)
}
