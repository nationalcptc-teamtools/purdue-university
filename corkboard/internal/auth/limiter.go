package auth

import (
	"net"
	"sync"
	"time"
)

const (
	MaxFails   = 10
	FailWindow = 5 * time.Minute
)

type Limiter struct {
	mu sync.Mutex
	m  map[string][]time.Time
}

func NewLimiter() *Limiter {
	return &Limiter{m: make(map[string][]time.Time)}
}

func (l *Limiter) Blocked(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(ip, now)) >= MaxFails
}

func (l *Limiter) Record(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.m[ip] = append(l.recent(ip, now), now)
}

func (l *Limiter) recent(ip string, now time.Time) []time.Time {
	cut := now.Add(-FailWindow)
	var out []time.Time
	for _, t := range l.m[ip] {
		if t.After(cut) {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		delete(l.m, ip)
	}
	return out
}

func RemoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
