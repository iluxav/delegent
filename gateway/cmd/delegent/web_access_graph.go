package main

import (
	"context"
	"fmt"
	"html/template"
	"sort"
	"strings"

	"delegent.dev/gateway"
	"delegent.dev/gateway/store"
)

// accessGraph draws the reach of a target as columns of boxes: who may call it on the left
// (you always; the agents its audience admits), the target itself, and — when the target is
// an agent — what it may call, then what those agents may call, out to graphDepth hops. An
// edge A → B means B's audience admits A. Only edges into the target and forward edges down
// the chain are drawn. The chain wins: an agent that is both reachable from the target and a
// caller of it is drawn once, downstream, marked "calls back", so the callers column holds
// only what is not already in the chain. Edges touching the target are emphasised; the
// callee's consent mode is the badge on its box. Server-rendered SVG.
//
// With t == nil it draws the whole map: every entry agent (one no agent can reach) in the
// first column after You, and everything reachable from them beyond.
func accessGraph(ctx context.Context, st store.Store, t *store.Target) template.HTML {
	ts, err := st.ListTargets(ctx)
	if err != nil {
		return ""
	}
	byID := map[string]*store.Target{}
	if t != nil {
		byID[t.ID] = t // the target itself is drawn even while disabled
	}
	for _, o := range ts {
		if o.Enabled {
			byID[o.ID] = o
		}
	}
	isAgent := func(id string) bool { o := byID[id]; return o != nil && o.Kind == gateway.TargetKindA2A }
	admits := func(callee, caller string) bool {
		c, ok := byID[callee]
		return ok && callee != caller && isAgent(caller) && store.Visible(ctx, st, &store.AgentKey{ID: "k", AgentTargetID: caller}, c)
	}
	sorted := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for id := range m {
			out = append(out, id)
		}
		sort.Strings(out)
		return out
	}

	// columns: [callers] [target] [reach 1] [reach 2] … — or, for the whole map, [You] [entry
	// agents and whatever no agent reaches] [reach 1] …
	const youID = "\x00you"
	layer := map[string]int{youID: 0}
	var frontier []string
	focus := ""
	if t != nil {
		focus = t.ID
		layer[t.ID] = 1
		frontier = []string{t.ID}
	} else {
		for id := range byID {
			reached := false
			for from := range byID {
				if isAgent(from) && admits(id, from) {
					reached = true
					break
				}
			}
			if !reached {
				layer[id] = 1
				frontier = append(frontier, id)
			}
		}
		sort.Strings(frontier)
	}
	const graphDepth = 4
	for d := 2; d <= 1+graphDepth && len(frontier) > 0; d++ {
		next := map[string]bool{}
		for _, from := range frontier {
			if !isAgent(from) {
				continue
			}
			for id := range byID {
				if _, seen := layer[id]; !seen && admits(id, from) {
					next[id] = true
				}
			}
		}
		frontier = frontier[:0]
		for _, id := range sorted(next) {
			layer[id] = d
			frontier = append(frontier, id)
		}
	}
	callers := map[string]bool{}   // admitted callers not already drawn in the chain
	callsBack := map[string]bool{} // chain members that may also call the target
	if focus != "" {
		for id := range byID {
			if !admits(focus, id) {
				continue
			}
			if _, inChain := layer[id]; inChain {
				callsBack[id] = true
			} else {
				callers[id] = true
				layer[id] = 0
			}
		}
	}
	cols := map[int][]string{}
	for id, l := range layer {
		cols[l] = append(cols[l], id)
	}
	for l := range cols {
		sort.Slice(cols[l], func(i, j int) bool {
			a, b := cols[l][i], cols[l][j]
			if a == youID || b == youID {
				return a == youID
			}
			return a < b
		})
	}
	ncols := 0
	for l := range cols {
		if l+1 > ncols {
			ncols = l + 1
		}
	}

	const bw, bh, gapX, gapY, pad = 192.0, 86.0, 48.0, 24.0, 16.0
	type box struct{ x, y float64 }
	pos := map[string]box{}
	height := 0.0
	for l := 0; l < ncols; l++ {
		h := float64(len(cols[l]))*(bh+gapY) - gapY
		if h > height {
			height = h
		}
	}
	for l := 0; l < ncols; l++ {
		n := float64(len(cols[l]))
		top := pad + (height-(n*(bh+gapY)-gapY))/2
		for i, id := range cols[l] {
			pos[id] = box{x: pad + float64(l)*(bw+gapX), y: top + float64(i)*(bh+gapY)}
		}
	}
	width := pad*2 + float64(ncols)*bw + float64(ncols-1)*gapX

	var b strings.Builder
	title := "The relationship map: who can call whom"
	if t != nil {
		title = "Who can call " + t.Name + " and what it can reach"
	}
	fmt.Fprintf(&b, `<svg class="access-graph-svg" viewBox="0 0 %.0f %.0f" style="--graph-width:%.0fpx" role="img" aria-label="%s">`, width, height+pad*2, width, template.HTMLEscapeString(title))
	b.WriteString(`<defs><marker id="ag-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L8 4L0 8z" fill="currentColor"/></marker></defs>`)
	edge := func(from, to string, strong bool) {
		a, c := pos[from], pos[to]
		x1, y1 := a.x+bw, a.y+bh/2
		x2, y2 := c.x, c.y+bh/2
		mx := (x1 + x2) / 2
		fmt.Fprintf(&b, `<path class="ag-edge%s" d="M%.1f %.1f C%.1f %.1f %.1f %.1f %.1f %.1f" marker-end="url(#ag-arrow)"/>`, strongCls(strong), x1, y1, mx, y1, mx, y2, x2-2, y2)
	}
	// you and every admitted caller → the target (or you → every entry); then only forward
	// edges down the chain
	if focus != "" {
		edge(youID, focus, true)
		for _, id := range sorted(callers) {
			edge(id, focus, true)
		}
	} else {
		for _, id := range frontier0(layer) {
			edge(youID, id, false)
		}
	}
	for from, lf := range layer {
		if lf < 1 {
			continue
		}
		for to, lt := range layer {
			if lt > lf && admits(to, from) {
				edge(from, to, from == focus)
			}
		}
	}

	for id, p := range pos {
		cls, label, sub, badge := "ag-node", "", "", ""
		switch {
		case id == youID:
			cls += " ag-you"
			label, sub = "You", "your own clients"
		default:
			o := byID[id]
			label = o.Name
			if o.Kind == gateway.TargetKindA2A {
				cls += " ag-agent"
				sub = "agent"
			} else {
				cls += " ag-mcp"
				sub = "MCP server"
			}
			if !strings.EqualFold(o.ID, o.Name) {
				sub += " · " + o.ID
			}
			if callsBack[id] {
				sub += " · calls back"
			}
			switch o.Consent {
			case store.ConsentAllow:
				badge = "never asks"
			case store.ConsentRemember:
				badge = "remembers"
			default:
				badge = "asks"
			}
			if id == focus {
				cls += " ag-self"
			}
		}
		fmt.Fprintf(&b, `<g class="%s" transform="translate(%.1f %.1f)">`, cls, p.x, p.y)
		if id != youID {
			fmt.Fprintf(&b, `<a href="/targets/%s/access" hx-get="/targets/%s/access" hx-target="#main" hx-push-url="true">`, template.HTMLEscapeString(id), template.HTMLEscapeString(id))
		}
		fmt.Fprintf(&b, `<title>%s · %s</title><rect width="%.0f" height="%.0f" rx="9"/><text class="ag-label" x="14" y="27">%s</text><text class="ag-sub" x="14" y="45">%s</text>`, template.HTMLEscapeString(label), template.HTMLEscapeString(sub), bw, bh, template.HTMLEscapeString(clip(label, 23)), template.HTMLEscapeString(clip(sub, 29)))
		if badge != "" {
			fmt.Fprintf(&b, `<path class="ag-divider" d="M14 55H%.0f"/><text class="ag-badge" x="14" y="73">%s</text>`, bw-14, badge)
		} else {
			b.WriteString(`<text class="ag-badge" x="14" y="73">operator access</text>`)
		}
		if id != youID {
			b.WriteString(`</a>`)
			if isAgent(id) {
				fmt.Fprintf(&b, `<a class="ag-run" href="/play/%s" hx-get="/play/%s" hx-target="#main" hx-push-url="true"><title>Run %s in the playground</title><text x="%.0f" y="73" text-anchor="end">run ▸</text></a>`, template.HTMLEscapeString(id), template.HTMLEscapeString(id), template.HTMLEscapeString(label), bw-14)
			}
		}
		b.WriteString(`</g>`)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// frontier0 lists the layer-1 nodes (the entries of a whole-map drawing), sorted.
func frontier0(layer map[string]int) []string {
	var out []string
	for id, l := range layer {
		if l == 1 {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func strongCls(strong bool) string {
	if strong {
		return " ag-strong"
	}
	return ""
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
