package main

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"delegent.dev/gateway"
)

// alertRow is one pending ask, normalized from live (PendingView) and parked
// (ConsentRequest) shapes into what the operator decides on.
type alertRow struct {
	id, target, agent, headline, intent string
	scopes                              []alertScope
	warnings                            []string
	parked                              bool
}

type alertScope struct {
	scope, human, risk string
	granted            bool // approval-picker state; all on by default
}

var ttlPresets = []int{15, 60, 240, 1440}
var budgetPresets = []float64{0, 1, 5, 25}

type alertsScreen struct {
	o    ops
	live bool

	rows    []alertRow
	cursor  int
	history []string // short strip of recent resolutions

	deciding  bool // approval picker open for rows[cursor]
	scopeCur  int
	ttlIdx    int // index into ttlPresets (default 60m)
	budgetIdx int
}

type consentsLoadedMsg struct{ b *consentBundle }
type resolvedMsg struct {
	id      string
	approve bool
	ok      bool
}

func newAlertsScreen(o ops, live bool) *alertsScreen {
	return &alertsScreen{o: o, live: live, ttlIdx: 1}
}

func (s *alertsScreen) capturing() bool { return s.deciding }

func (s *alertsScreen) init() tea.Cmd { return s.load() }

func (s *alertsScreen) load() tea.Cmd {
	return func() tea.Msg {
		b, err := s.o.Consents(context.Background())
		if err != nil {
			return errMsg{err}
		}
		return consentsLoadedMsg{b}
	}
}

func (s *alertsScreen) update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case consentsLoadedMsg:
		s.rows = s.rows[:0]
		for _, p := range msg.b.Live {
			row := alertRow{id: p.ID, target: p.TargetID, agent: p.AgentName, headline: p.Headline, intent: p.Intent, warnings: p.OverAskWarnings}
			for _, sc := range p.Scopes {
				row.scopes = append(row.scopes, alertScope{scope: sc.Scope, human: sc.Human, risk: sc.Risk, granted: true})
			}
			s.rows = append(s.rows, row)
		}
		for _, p := range msg.b.Parked {
			row := alertRow{id: p.ID, target: p.TargetID, agent: p.AgentName, headline: p.Headline, intent: p.Intent, parked: true}
			for _, sc := range p.Scopes {
				row.scopes = append(row.scopes, alertScope{scope: sc, granted: true})
			}
			s.rows = append(s.rows, row)
		}
		if s.cursor >= len(s.rows) {
			s.cursor = 0
		}
		return s, nil

	case consentStreamMsg:
		// the root forwards stream deltas here from any tab; re-list for authoritative state
		if msg.ev.Type == "pending" {
			return s, tea.Batch(s.load(), refreshAlertCount(s.o))
		}
		return s, tea.Batch(s.load(), refreshAlertCount(s.o))

	case resolvedMsg:
		verb := "denied"
		if msg.approve {
			verb = "approved"
		}
		if !msg.ok {
			s.history = append(s.history, msg.id+" — no live ask (expired or agent gave up)")
			return s, tea.Batch(flash("no live ask held that id"), s.load(), refreshAlertCount(s.o))
		}
		s.history = append(s.history, msg.id+" "+verb)
		if len(s.history) > 5 {
			s.history = s.history[len(s.history)-5:]
		}
		return s, tea.Batch(flash(msg.id+" "+verb), s.load(), refreshAlertCount(s.o))

	case tea.KeyMsg:
		if s.deciding {
			return s.updateDeciding(msg)
		}
		switch msg.String() {
		case "up", "k":
			if s.cursor > 0 {
				s.cursor--
			}
		case "down", "j":
			if s.cursor < len(s.rows)-1 {
				s.cursor++
			}
		case "r":
			return s, s.load()
		case "a":
			if len(s.rows) > 0 {
				if !s.live {
					return s, func() tea.Msg { return errMsg{errOffline} }
				}
				s.deciding = true
				s.scopeCur = 0
				for i := range s.rows[s.cursor].scopes {
					s.rows[s.cursor].scopes[i].granted = true
				}
			}
		case "d":
			if len(s.rows) > 0 {
				if !s.live {
					return s, func() tea.Msg { return errMsg{errOffline} }
				}
				return s, s.resolve(s.rows[s.cursor], false, nil)
			}
		}
	}
	return s, nil
}

func (s *alertsScreen) updateDeciding(msg tea.KeyMsg) (screen, tea.Cmd) {
	row := &s.rows[s.cursor]
	switch msg.String() {
	case "esc":
		s.deciding = false
	case "up", "k":
		if s.scopeCur > 0 {
			s.scopeCur--
		}
	case "down", "j":
		if s.scopeCur < len(row.scopes)-1 {
			s.scopeCur++
		}
	case " ":
		if len(row.scopes) > 0 {
			row.scopes[s.scopeCur].granted = !row.scopes[s.scopeCur].granted
		}
	case "t":
		s.ttlIdx = (s.ttlIdx + 1) % len(ttlPresets)
	case "b":
		s.budgetIdx = (s.budgetIdx + 1) % len(budgetPresets)
	case "enter":
		var granted []string
		for _, sc := range row.scopes {
			if sc.granted {
				granted = append(granted, sc.scope)
			}
		}
		if len(granted) == 0 {
			return s, flash("nothing selected — space toggles scopes, or esc + d to deny")
		}
		s.deciding = false
		return s, s.resolve(*row, true, granted)
	}
	return s, nil
}

func (s *alertsScreen) resolve(row alertRow, approve bool, granted []string) tea.Cmd {
	ttl := ttlPresets[s.ttlIdx]
	budget := budgetPresets[s.budgetIdx]
	return func() tea.Msg {
		ok, err := s.o.Resolve(context.Background(), row.id, approve, granted, ttl, budget)
		if err != nil {
			return errMsg{err}
		}
		return resolvedMsg{id: row.id, approve: approve, ok: ok}
	}
}

func (s *alertsScreen) hints() string {
	if s.deciding {
		return "space toggle scope · t TTL · b budget · enter approve · esc cancel"
	}
	if !s.live {
		return "offline: view-only (start the gateway to approve) · r reload"
	}
	return "↑↓ select · a approve · d deny · r reload"
}

func (s *alertsScreen) view(width, height int) string {
	var b strings.Builder
	if len(s.rows) == 0 {
		b.WriteString(styDim.Render("\n  no pending approvals"))
	} else if !s.deciding {
		b.WriteString(styBold.Render("  ↑↓ select   a approve   d deny") +
			styDim.Render("   — the agent is waiting on you; denials and approvals land instantly") + "\n\n")
	} else {
		b.WriteString(styBold.Render("  approve: space toggles a scope · t TTL · b budget · enter confirm · esc back") + "\n\n")
	}
	for i, row := range s.rows {
		kind := styStatusOff.Render("LIVE  ")
		if row.parked {
			kind = styDim.Render("parked")
		}
		head := row.headline
		if head == "" {
			var scopes []string
			for _, sc := range row.scopes {
				scopes = append(scopes, sc.scope)
			}
			head = strings.Join(scopes, " ")
		}
		marker := "  "
		if i == s.cursor {
			marker = "▸ "
		}
		line := fmt.Sprintf("%s%-14s %s %-12s %-12s %s", marker, row.id, kind, truncate(row.agent, 12), truncate(row.target, 12), head)
		if i == s.cursor {
			line = styCursor.Render(line)
		}
		b.WriteString(line + "\n")
		if row.intent != "" {
			b.WriteString(styDim.Render("                 why: "+row.intent) + "\n")
		}
		for _, w := range row.warnings {
			b.WriteString(styRiskHigh.Render("                 ⚠ "+w) + "\n")
		}
		if s.deciding && i == s.cursor {
			b.WriteString(s.viewPicker(row))
		}
	}
	if len(s.history) > 0 {
		b.WriteString("\n" + styDim.Render("  recent: "+strings.Join(s.history, " · ")) + "\n")
	}
	return b.String()
}

func (s *alertsScreen) viewPicker(row alertRow) string {
	var b strings.Builder
	for j, sc := range row.scopes {
		box := "[ ]"
		if sc.granted {
			box = "[x]"
		}
		line := fmt.Sprintf("      %s %-24s %s %s", box, sc.scope, riskStyle(sc.risk).Render(sc.risk), styDim.Render(sc.human))
		if j == s.scopeCur {
			line = styCursor.Render(line)
		}
		b.WriteString(line + "\n")
	}
	b.WriteString(fmt.Sprintf("      TTL %dm (t) · budget $%.0f (b) · enter approves the checked scopes\n",
		ttlPresets[s.ttlIdx], budgetPresets[s.budgetIdx]))
	return b.String()
}

// ensure the gateway import stays used even if PendingView fields shift
var _ gateway.PendingView
