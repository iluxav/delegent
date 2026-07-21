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
		seen := map[string]bool{}
		for _, p := range msg.b.Live {
			row := alertRow{id: p.ID, target: p.TargetID, agent: p.AgentName, headline: p.Headline, intent: p.Intent, warnings: p.OverAskWarnings}
			for _, sc := range p.Scopes {
				row.scopes = append(row.scopes, alertScope{scope: sc.Scope, human: sc.Human, risk: sc.Risk, granted: true})
			}
			s.rows = append(s.rows, row)
			seen[p.ID] = true
		}
		for _, p := range msg.b.Parked {
			if seen[p.ID] {
				continue // the live nonce and its durable row are ONE ask — never show it twice
			}
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
		return hintBar(kb("space", "toggle scope"), kb("t", "TTL"), kb("b", "budget"),
			kb("enter", "approve"), kb("esc", "cancel"))
	}
	if !s.live {
		return styDim.Render("offline: view-only (start the gateway to approve)") + " " + hintBar(kb("r", "reload"))
	}
	return hintBar(kb("↑↓", "select"), kb("a", "approve"), kb("d", "deny"), kb("r", "reload"))
}

// cleanWarning tidies engine over-ask text for display (an empty inferred-needs list renders
// as a dangling "only requires: ." upstream — display-only fix).
func cleanWarning(w string) string {
	w = strings.TrimSpace(w)
	w = strings.ReplaceAll(w, "only requires: .", "doesn't clearly require it.")
	return w
}

func (s *alertsScreen) view(width, height int) string {
	var b strings.Builder
	if len(s.rows) == 0 {
		b.WriteString("\n" + styDim.Render("  no pending approvals — new asks appear here the moment an agent needs you") + "\n")
		if len(s.history) > 0 {
			b.WriteString("\n" + styDim.Render("  recent: "+strings.Join(s.history, " · ")) + "\n")
		}
		return b.String()
	}

	if s.deciding {
		b.WriteString("  " + styHead.Render("approve: space toggles a scope · t TTL · b budget · enter confirm · esc back") + "\n\n")
	} else {
		b.WriteString("  " + styHead.Render("↑↓ select · a approve · d deny") +
			styDim.Render("  — the agent is waiting on you") + "\n\n")
	}

	cardW := width - 6
	if cardW > 100 {
		cardW = 100
	}
	if cardW < 40 {
		cardW = 40
	}
	inner := cardW - 4 // border + padding

	for i, row := range s.rows {
		selected := i == s.cursor
		kind := styStatusOff.Render("LIVE")
		if row.parked {
			kind = styDim.Render("parked")
		}
		marker := "  "
		if selected {
			marker = styBold.Render("▸ ")
		}

		head := row.headline
		if head == "" {
			var scopes []string
			for _, sc := range row.scopes {
				scopes = append(scopes, sc.scope)
			}
			head = "wants: " + strings.Join(scopes, ", ")
		}

		var card strings.Builder
		title := styBold.Render(shortID(row.id)) + "  " + kind + styDim.Render("  "+truncate(row.agent, 20)+" → "+truncate(row.target, 20))
		card.WriteString(title + "\n")
		card.WriteString(truncate(head, inner) + "\n")
		// the headline already carries the agent's why — repeat it only when it adds anything
		if row.intent != "" && !strings.Contains(head, row.intent) {
			card.WriteString(styDim.Render(truncate("why: "+row.intent, inner)) + "\n")
		}
		for _, w := range row.warnings {
			card.WriteString(styRiskHigh.Render(truncate("⚠ "+cleanWarning(w), inner)) + "\n")
		}
		if s.deciding && selected {
			card.WriteString(s.viewPicker(row, inner))
		} else if selected {
			card.WriteString(styDim.Render("a approve · d deny") + "\n")
		}

		box := styCardOff
		if selected {
			box = styCardOn
		}
		rendered := box.Width(cardW).Render(strings.TrimRight(card.String(), "\n"))
		// hang the selection marker off the card's first line
		lines := strings.Split(rendered, "\n")
		for li, ln := range lines {
			if li == 0 {
				b.WriteString(marker + ln + "\n")
			} else {
				b.WriteString("  " + ln + "\n")
			}
		}
	}
	if len(s.history) > 0 {
		b.WriteString(styDim.Render("  recent: "+strings.Join(s.history, " · ")) + "\n")
	}
	return b.String()
}

func (s *alertsScreen) viewPicker(row alertRow, inner int) string {
	var b strings.Builder
	b.WriteString(styRule.Render(strings.Repeat("─", max(1, inner))) + "\n")
	for j, sc := range row.scopes {
		box := "[ ]"
		if sc.granted {
			box = "[x]"
		}
		line := box + " " + padCell(sc.scope, 24) + " " + riskStyle(sc.risk).Render(padCell(sc.risk, 7)) + " " + styDim.Render(truncate(sc.human, inner-38))
		if j == s.scopeCur {
			line = styCursor.Render(padCell(box+" "+sc.scope, 25)) + " " + riskStyle(sc.risk).Render(padCell(sc.risk, 7)) + " " + styDim.Render(truncate(sc.human, inner-38))
		}
		b.WriteString(line + "\n")
	}
	b.WriteString(styDim.Render(fmt.Sprintf("TTL %dm (t) · budget $%.0f (b) · enter approves the checked scopes", ttlPresets[s.ttlIdx], budgetPresets[s.budgetIdx])) + "\n")
	return b.String()
}

// ensure the gateway import stays used even if PendingView fields shift
var _ gateway.PendingView
