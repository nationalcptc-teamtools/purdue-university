package scope

import (
	"fmt"
	"net/netip"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Zone string

const (
	ZoneIn      Zone = "in"
	ZoneCaution Zone = "caution"
	ZoneOut     Zone = "out"
	ZoneUnknown Zone = "unknown"
)

type Spec struct {
	Engagement string   `yaml:"engagement"`
	InScope    []string `yaml:"in_scope"`
	Caution    []string `yaml:"caution"`
	OutOfScope []string `yaml:"out_of_scope"`
}

func Load(data []byte) (*Scope, error) {
	var spec Spec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("scope: %w", err)
	}
	sc := &Scope{Engagement: spec.EngineSafe(), outRaw: spec.OutOfScope, cautionRaw: spec.Caution, inRaw: spec.InScope}
	var err error
	if sc.out, err = parseMatchers(spec.OutOfScope); err != nil {
		return nil, fmt.Errorf("out_of_scope: %w", err)
	}
	if sc.caution, err = parseMatchers(spec.Caution); err != nil {
		return nil, fmt.Errorf("caution: %w", err)
	}
	if sc.in, err = parseMatchers(spec.InScope); err != nil {
		return nil, fmt.Errorf("in_scope: %w", err)
	}
	return sc, nil
}

func (s *Spec) EngineSafe() string {
	if s.Engagement == "" {
		return "(unnamed)"
	}
	return s.Engagement
}

type Scope struct {
	Engagement string
	in         []matcher
	caution    []matcher
	out        []matcher
	inRaw      []string
	outRaw     []string
	cautionRaw []string
}

func (s *Scope) YAML() ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("scope: no active scope")
	}
	return yaml.Marshal(Spec{Engagement: s.Engagement, InScope: s.inRaw, Caution: s.cautionRaw, OutOfScope: s.outRaw})
}

func (s *Scope) Check(targets ...string) []TargetResult {
	out := make([]TargetResult, 0, len(targets))
	for _, t := range targets {
		out = append(out, s.CheckTarget(t))
	}
	return out
}

func (s *Scope) CheckTarget(t string) TargetResult {
	t = strings.TrimSpace(t)
	res := TargetResult{Value: t, Zone: ZoneUnknown}
	if addr, err := netip.ParseAddr(t); err == nil {
		res.IsIP = true
		res.Zone = s.ZoneOf(addr, nil)
		return res
	}
	if p, err := netip.ParsePrefix(t); err == nil {
		res.IsIP = true
		res.Zone, res.Reason = s.classifyInterval(p.Masked().Addr(), lastInPrefix(p))
		return res
	}
	if lo, hi, ok := parseRange(t); ok {
		res.IsIP = true
		res.Zone, res.Reason = s.classifyInterval(lo, hi)
		return res
	}
	res.Zone = s.ZoneOfHostname(t)
	return res
}

type interval struct{ lo, hi netip.Addr }

func (s *Scope) classifyInterval(lo, hi netip.Addr) (Zone, string) {
	t := interval{lo: lo, hi: hi}
	if s.overlapsAny(s.out, t) {
		return ZoneOut, "intersects an out_of_scope entry"
	}
	if s.overlapsAny(s.caution, t) {
		return ZoneCaution, "intersects a caution entry"
	}
	if s.coveredBy(s.in, t) {
		return ZoneIn, "fully covered by in_scope"
	}
	return ZoneUnknown, "not fully covered by in_scope"
}

func (s *Scope) overlapsAny(ms []matcher, t interval) bool {
	for _, m := range ms {
		if it, ok := m.interval(); ok && intervalsOverlap(it, t) {
			return true
		}
	}
	return false
}

func (s *Scope) coveredBy(ms []matcher, t interval) bool {
	var ivs []interval
	for _, m := range ms {
		if it, ok := m.interval(); ok {
			ivs = append(ivs, it)
		}
	}
	sort.Slice(ivs, func(i, j int) bool { return addrCmp(ivs[i].lo, ivs[j].lo) < 0 })
	var merged []interval
	for _, iv := range ivs {
		if n := len(merged); n > 0 && addrCmp(iv.lo, merged[n-1].hi) <= 0 {
			if addrCmp(iv.hi, merged[n-1].hi) > 0 {
				merged[n-1].hi = iv.hi
			}
			continue
		}
		merged = append(merged, iv)
	}
	pos := t.lo
	for _, iv := range merged {
		if addrCmp(iv.lo, pos) > 0 {
			return false
		}
		if addrCmp(iv.hi, t.hi) >= 0 {
			return true
		}
		if addrCmp(iv.hi, pos) > 0 {
			pos = iv.hi
		}
	}
	return false
}

func intervalsOverlap(a, b interval) bool {
	return addrCmp(a.lo, b.hi) <= 0 && addrCmp(b.lo, a.hi) <= 0
}

type TargetResult struct {
	Value  string
	IsIP   bool
	Zone   Zone
	Reason string
}

func (s *Scope) NmapExclude() string {
	var b strings.Builder
	b.WriteString("# cork scope exclude — out_of_scope + caution\n")
	for _, e := range s.outRaw {
		b.WriteString(e)
		b.WriteByte('\n')
	}
	for _, e := range s.cautionRaw {
		b.WriteString(e)
		b.WriteByte('\n')
	}
	return b.String()
}

func (s *Scope) ZoneOf(addr netip.Addr, hostnames []string) Zone {
	if s.matchAny(s.out, addr, hostnames) {
		return ZoneOut
	}
	if s.matchAny(s.caution, addr, hostnames) {
		return ZoneCaution
	}
	if s.matchAny(s.in, addr, hostnames) {
		return ZoneIn
	}
	return ZoneUnknown
}

func (s *Scope) ZoneOfHostname(name string) Zone {
	var hns = []string{name}
	if s.matchAny(s.out, netip.Addr{}, hns) {
		return ZoneOut
	}
	if s.matchAny(s.caution, netip.Addr{}, hns) {
		return ZoneCaution
	}
	if s.matchAny(s.in, netip.Addr{}, hns) {
		return ZoneIn
	}
	return ZoneUnknown
}

func (s *Scope) ZoneOfIP(ip string, hostnames []string) Zone {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return s.ZoneOfHostname(ip)
	}
	return s.ZoneOf(addr, hostnames)
}

type matcherKind int

const (
	mIP matcherKind = iota
	mCIDR
	mRange
	mGlob
)

type matcher struct {
	kind   matcherKind
	ip     netip.Addr
	prefix netip.Prefix
	lo     netip.Addr
	hi     netip.Addr
	glob   string
}

func (m matcher) interval() (interval, bool) {
	switch m.kind {
	case mIP:
		return interval{lo: m.ip, hi: m.ip}, true
	case mCIDR:
		return interval{lo: m.prefix.Masked().Addr(), hi: lastInPrefix(m.prefix)}, true
	case mRange:
		return interval{lo: m.lo, hi: m.hi}, true
	}
	return interval{}, false
}

func parseMatchers(entries []string) ([]matcher, error) {
	out := make([]matcher, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		m, err := parseEntry(e)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func parseEntry(e string) (matcher, error) {
	if addr, err := netip.ParseAddr(e); err == nil {
		return matcher{kind: mIP, ip: addr}, nil
	}
	if p, err := netip.ParsePrefix(e); err == nil {
		return matcher{kind: mCIDR, prefix: p}, nil
	}
	if lo, hi, ok := parseRange(e); ok {
		return matcher{kind: mRange, lo: lo, hi: hi}, nil
	}
	return matcher{kind: mGlob, glob: strings.ToLower(e)}, nil
}

func (m matcher) match(addr netip.Addr, hostnames []string) bool {
	switch m.kind {
	case mIP:
		return addr.IsValid() && addr == m.ip
	case mCIDR:
		return addr.IsValid() && m.prefix.Contains(addr)
	case mRange:
		if !addr.IsValid() {
			return false
		}
		cmp := func(a, b netip.Addr) int {
			ab, bb := a.As16(), b.As16()
			for i := range ab {
				if ab[i] != bb[i] {
					if ab[i] < bb[i] {
						return -1
					}
					return 1
				}
			}
			return 0
		}
		return cmp(addr, m.lo) >= 0 && cmp(addr, m.hi) <= 0
	case mGlob:
		for _, h := range hostnames {
			if matched, _ := path.Match(m.glob, strings.ToLower(h)); matched {
				return true
			}
		}
		return false
	}
	return false
}

func (s *Scope) matchAny(ms []matcher, addr netip.Addr, hostnames []string) bool {
	for _, m := range ms {
		if m.match(addr, hostnames) {
			return true
		}
	}
	return false
}

func parseRange(e string) (lo, hi netip.Addr, ok bool) {
	i := strings.LastIndex(e, "-")
	if i <= 0 || i == len(e)-1 {
		return
	}
	a, err1 := netip.ParseAddr(strings.TrimSpace(e[:i]))
	b, err2 := netip.ParseAddr(strings.TrimSpace(e[i+1:]))
	if err1 != nil || err2 != nil {
		return
	}
	if addrCmp(a, b) > 0 {
		a, b = b, a
	}
	return a, b, true
}

func addrCmp(a, b netip.Addr) int {
	ab, bb := a.As16(), b.As16()
	for i := range ab {
		if ab[i] != bb[i] {
			if ab[i] < bb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func lastInPrefix(p netip.Prefix) netip.Addr {
	bits := p.Bits()
	b := p.Masked().Addr().As16()
	total, start := 128, 0
	if p.Addr().Is4() {

		total, start = 32, 12
	}
	for i := range total - bits {
		pos := bits + i
		b[start+pos/8] |= byte(1 << (7 - pos%8))
	}
	if a, ok := netip.AddrFromSlice(b[:]); ok {
		return a
	}
	return p.Masked().Addr()
}
