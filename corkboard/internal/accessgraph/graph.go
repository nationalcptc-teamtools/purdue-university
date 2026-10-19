package accessgraph

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
	"time"

	"corkboard/internal/store"
)

const MaxEdges = 150

type Node struct {
	Key   string `json:"key"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Layer int    `json:"layer"`
	Row   int    `json:"row"`
}

type Graph struct {
	Nodes     []Node             `json:"nodes"`
	Edges     []store.AccessEdge `json:"edges"`
	Truncated int                `json:"truncated,omitempty"`
}

const unknownKey = "unknown"

func Build(edges []store.AccessEdge) Graph {
	g := Graph{Edges: edges}
	if len(edges) > MaxEdges {
		g.Truncated = len(edges) - MaxEdges
		g.Edges = edges[:MaxEdges]
	}
	nodes := map[string]*Node{}
	var order []string
	add := func(key, label string) {
		if _, ok := nodes[key]; ok {
			return
		}
		kind, _, _ := strings.Cut(key, ":")
		nodes[key] = &Node{Key: key, Kind: kind, Label: label}
		order = append(order, key)
	}
	src := func(e store.AccessEdge) string {
		if e.Src == "" {
			return unknownKey
		}
		return e.Src
	}
	for _, e := range g.Edges {
		add(src(e), e.SrcLabel)
		add(e.Dst, e.DstLabel)
	}

	for range len(nodes) {
		changed := false
		for _, e := range g.Edges {
			s, d := nodes[src(e)], nodes[e.Dst]
			if s != d && d.Layer < s.Layer+1 && s.Layer+1 < len(nodes) {
				d.Layer = s.Layer + 1
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	rows := map[int]int{}
	for _, k := range order {
		n := nodes[k]
		n.Row = rows[n.Layer]
		rows[n.Layer]++
		g.Nodes = append(g.Nodes, *n)
	}
	return g
}

const (
	colW, rowH       = 340, 76
	nodeW, nodeH     = 180, 40
	marginX, marginY = 20, 30
)

func (n Node) xy() (float64, float64) {
	return float64(marginX + n.Layer*colW), float64(marginY + n.Row*rowH)
}

const Style = `svg.ag text{font:12px sans-serif;fill:#1d2733}
svg.ag .n rect{fill:#f4f6f8;stroke:#5b6b7b;stroke-width:1.2}
svg.ag .n.vantage rect{fill:#e7f0ff}
svg.ag .n.cred rect{fill:#fff6e0}
svg.ag .n.unknown rect{fill:#fff;stroke-dasharray:4 3}
svg.ag .e path{fill:none;stroke-width:1.6}
svg.ag .e text{font-size:10px;fill:#3b4754}
svg.ag .reach path{stroke:#7a8794}
svg.ag .auth path{stroke:#2f6fd0}
svg.ag .shell path{stroke:#c0392b;stroke-width:2.4}
svg.ag .cred_found path,svg.ag .cred_used path{stroke:#b07d10}
svg.ag .tunnel path{stroke:#6c3fb5}
svg.ag .ended path{stroke-dasharray:6 4;opacity:.6}
svg.ag .derived path{opacity:.7}
@media (prefers-color-scheme:dark){svg.ag text{fill:#dfe6ee}svg.ag .n rect{fill:#1f2a35;stroke:#8899aa}svg.ag .n.vantage rect{fill:#1d3050}svg.ag .n.cred rect{fill:#3a2f12}svg.ag .n.unknown rect{fill:#141b22}svg.ag .e text{fill:#b8c4d0}}
`

func (g Graph) SVG(title string, links, embedStyle bool) []byte {
	var b bytes.Buffer
	w, h := 400, 120
	pos := map[string]Node{}
	for _, n := range g.Nodes {
		pos[n.Key] = n
		x, y := n.xy()
		w = max(w, int(x)+nodeW+marginX)
		h = max(h, int(y)+nodeH+marginY)
	}
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" class="ag" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="%s">`, w, h, w, h, esc(title))
	if embedStyle {
		b.WriteString("<style>" + Style + "</style>")
	}

	const maxLabels = 3
	incoming := map[string]int{}
	b.WriteString(`<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#5b6b7b"/></marker></defs>`)
	for _, e := range g.Edges {
		s, d := pos[srcKey(e)], pos[e.Dst]
		sx, sy := s.xy()
		dx, dy := d.xy()
		x1, y1, x2, y2 := sx+nodeW, sy+nodeH/2, dx, dy+nodeH/2
		if d.Layer <= s.Layer {
			x2 = dx + nodeW/2
			y2 = dy + nodeH
		}
		cls := "e " + e.Kind
		if e.State == "ended" {
			cls += " ended"
		}
		if e.Derived {
			cls += " derived"
		}
		mid := (x1 + x2) / 2
		fmt.Fprintf(&b, `<g class="%s"><title>%s</title><path d="M%.0f %.0f C%.0f %.0f %.0f %.0f %.0f %.0f" marker-end="url(#arrow)"/>`,
			cls, esc(edgeTitle(e)), x1, y1, mid, y1, mid, y2, x2, y2)
		if k := incoming[e.Dst]; k < maxLabels {
			incoming[e.Dst]++
			if d.Layer <= s.Layer {
				fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" text-anchor="middle">%s</text>`, x2, y2+14+12*float64(k), esc(edgeLabel(e)))
			} else {
				fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" text-anchor="end">%s</text>`, x2-10, y2-6-12*float64(k), esc(edgeLabel(e)))
			}
		}
		b.WriteString(`</g>`)
	}
	for _, n := range g.Nodes {
		x, y := n.xy()
		label := n.Label
		if n.Key == unknownKey {
			label = "unknown source"
		}
		if len(label) > 28 {
			label = label[:27] + "…"
		}
		open, closeTag := "", ""
		if href := nodeHref(n); links && href != "" {
			open, closeTag = `<a href="`+esc(href)+`">`, `</a>`
		}
		fmt.Fprintf(&b, `%s<g class="n %s"><title>%s</title><rect x="%.0f" y="%.0f" width="%d" height="%d" rx="6"/><text x="%.0f" y="%.0f">%s</text></g>%s`,
			open, esc(n.Kind), esc(n.Key+" "+n.Label), x, y, nodeW, nodeH, x+10, y+nodeH/2+4, esc(label), closeTag)
	}
	b.WriteString(`</svg>`)
	return b.Bytes()
}

func srcKey(e store.AccessEdge) string {
	if e.Src == "" {
		return unknownKey
	}
	return e.Src
}

func nodeHref(n Node) string {
	switch n.Kind {
	case "host":
		return "/hosts/" + n.Label
	case "service", "application":
		return "/work?target=" + n.Key
	case "cred":
		return "/creds"
	}
	return ""
}

func edgeLabel(e store.AccessEdge) string {
	parts := []string{e.Kind}
	if e.Level != "" {
		parts = append(parts, e.Level)
	}
	if e.OccurredAt != nil {
		parts = append(parts, Stamp(*e.OccurredAt))
	}
	return strings.Join(parts, " ")
}

func edgeTitle(e store.AccessEdge) string {
	t := fmt.Sprintf("%s: %s → %s by %s (%s)", e.Key, e.SrcLabel, e.DstLabel, e.Actor, e.Source)
	if e.Note != "" {
		t += " — " + e.Note
	}
	if e.EndedAt != nil {
		t += fmt.Sprintf("; ended %s: %s", Stamp(*e.EndedAt), e.EndReason)
	}
	return t
}

func Stamp(ms int64) string { return time.UnixMilli(ms).UTC().Format("01-02 15:04Z") }

func esc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return strings.ReplaceAll(b.String(), `"`, "&#34;")
}

func Markdown(title string, edges []store.AccessEdge) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# %s\n\n", title)
	b.WriteString("| When (UTC) | Edge | Kind | Level | From | To | By | Via | State | Note |\n|---|---|---|---|---|---|---|---|---|---|\n")
	sorted := append([]store.AccessEdge(nil), edges...)
	sort.SliceStable(sorted, func(i, j int) bool { return when(sorted[i]) < when(sorted[j]) })
	cell := func(s string) string { return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s) }
	for _, e := range sorted {
		at := "unknown"
		if e.OccurredAt != nil {
			at = time.UnixMilli(*e.OccurredAt).UTC().Format("2006-01-02 15:04")
		}
		key := e.Key
		if e.Derived {
			key += " (derived)"
		}
		via := ""
		if e.ViaEdgeID != nil {
			via = fmt.Sprintf("edge:%d", *e.ViaEdgeID)
		}
		state := e.State
		if e.SupersededBy != nil {
			state = fmt.Sprintf("corrected by edge:%d", *e.SupersededBy)
		} else if e.EndedAt != nil {
			state = fmt.Sprintf("ended %s (%s)", time.UnixMilli(*e.EndedAt).UTC().Format("2006-01-02 15:04"), e.EndReason)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", at, key, e.Kind, e.Level, cell(e.SrcLabel), cell(e.DstLabel), cell(e.Actor), via, cell(state), cell(e.Note))
	}
	return b.Bytes()
}

func when(e store.AccessEdge) int64 {
	if e.OccurredAt != nil {
		return *e.OccurredAt
	}
	return e.RecordedAt
}

func Times(edges []store.AccessEdge) []int64 {
	seen := map[int64]bool{}
	for _, e := range edges {
		seen[when(e)] = true
		if e.EndedAt != nil {
			seen[*e.EndedAt] = true
		}
	}
	out := make([]int64, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
