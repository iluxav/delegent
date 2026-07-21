package main

// The dashboard shell: tab bar, status line, footer, global consent-alert badge. Each tab is
// a screen owning its state and keymap; the root routes messages, sizes, and the live
// consent stream. All I/O rides tea.Cmds through the ops interface — Update never blocks.

import (
	"context"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"delegent.dev/gateway"
)

// --- shared styles ---

var (
	styTabActive = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("57")).Padding(0, 1)
	styTab       = lipgloss.NewStyle().Foreground(lipgloss.Color("246")).Padding(0, 1)
	styBrand     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("183"))
	styBadge     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("161")).Padding(0, 1)
	styRule      = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
	styHead      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("250"))
	styCardOn    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("57")).Padding(0, 1)
	styCardOff   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("238")).Padding(0, 1)
	styStatusOK  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styStatusOff = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styErr       = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	styDim       = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	styBold      = lipgloss.NewStyle().Bold(true)
	styCursor    = lipgloss.NewStyle().Background(lipgloss.Color("237"))
	styRiskHigh  = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	styRiskMed   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styRiskLow   = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styBox       = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2)
)

// padCell truncates and right-pads PLAIN text to exactly w columns. Always pad before
// styling: ANSI escapes count as characters in fmt-width math, which is how columns drift.
func padCell(s string, w int) string {
	if w <= 0 {
		return ""
	}
	s = truncate(s, w)
	if n := w - lipgloss.Width(s); n > 0 {
		s += strings.Repeat(" ", n)
	}
	return s
}

// shortID renders a long nonce id as a stable, readable handle.
func shortID(id string) string {
	if len(id) > 10 {
		return id[:10] + "…"
	}
	return id
}

func riskStyle(risk string) lipgloss.Style {
	switch risk {
	case "high":
		return styRiskHigh
	case "low":
		return styRiskLow
	}
	return styRiskMed
}

// --- shared messages ---

type errMsg struct{ err error }
type flashMsg struct{ text string }
type consentStreamMsg struct{ ev gateway.ConsentEvent }
type consentStreamClosedMsg struct{}
type clearFlashMsg struct{}

// screen is one tab's model.
type screen interface {
	init() tea.Cmd
	update(msg tea.Msg) (screen, tea.Cmd)
	view(width, height int) string
	hints() string
}

// --- root model ---

type rootModel struct {
	o       ops
	tabs    []string
	active  int
	screens []screen

	width, height int
	flash         string
	flashErr      bool
	pendingAlerts int

	stream       <-chan gateway.ConsentEvent
	streamCancel func()
	live         bool
}

func newRootModel(o ops) *rootModel {
	r := &rootModel{
		o:    o,
		tabs: []string{"Targets", "Keys", "Audit", "Alerts"},
		live: o.Mode() != "offline",
	}
	r.screens = []screen{newTargetsScreen(o), newKeysScreen(o), newAuditScreen(o, r.live), newAlertsScreen(o, r.live)}
	return r
}

func (r *rootModel) Init() tea.Cmd {
	cmds := []tea.Cmd{r.screens[0].init()}
	if r.live {
		cmds = append(cmds, r.openStream(), refreshAlertCount(r.o))
	}
	return tea.Batch(cmds...)
}

func (r *rootModel) openStream() tea.Cmd {
	return func() tea.Msg {
		ch, cancel, err := r.o.StreamConsents(context.Background())
		if err != nil {
			return consentStreamClosedMsg{}
		}
		r.stream = ch
		r.streamCancel = cancel
		return waitStream(ch)()
	}
}

// waitStream blocks on the next stream event (a tea.Cmd runs on its own goroutine).
func waitStream(ch <-chan gateway.ConsentEvent) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return consentStreamClosedMsg{}
		}
		return consentStreamMsg{ev: ev}
	}
}

type alertCountMsg struct{ n int }

func refreshAlertCount(o ops) tea.Cmd {
	return func() tea.Msg {
		b, err := o.Consents(context.Background())
		if err != nil {
			return errMsg{err}
		}
		return alertCountMsg{n: len(b.Live) + len(b.Parked)}
	}
}

func flash(text string) tea.Cmd {
	return tea.Batch(
		func() tea.Msg { return flashMsg{text} },
		tea.Tick(4*time.Second, func(time.Time) tea.Msg { return clearFlashMsg{} }),
	)
}

func bell() tea.Cmd {
	return func() tea.Msg { _, _ = os.Stderr.WriteString("\a"); return nil }
}

func (r *rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		r.width, r.height = msg.Width, msg.Height
		return r, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			// screens in an input/modal state swallow keys first — root only quits when the
			// active screen reports it is navigable (captures() = false).
			if !captures(r.screens[r.active]) {
				if r.streamCancel != nil {
					r.streamCancel()
				}
				return r, tea.Quit
			}
		case "tab", "shift+tab":
			if !captures(r.screens[r.active]) {
				d := 1
				if msg.String() == "shift+tab" {
					d = len(r.tabs) - 1
				}
				r.active = (r.active + d) % len(r.tabs)
				return r, r.screens[r.active].init()
			}
		}

	case flashMsg:
		r.flash, r.flashErr = msg.text, false
		return r, nil
	case errMsg:
		r.flash, r.flashErr = msg.err.Error(), true
		return r, nil
	case clearFlashMsg:
		r.flash = ""
		return r, nil

	case alertCountMsg:
		r.pendingAlerts = msg.n
		return r, nil

	case consentStreamMsg:
		var cmds []tea.Cmd
		if msg.ev.Type == "pending" {
			r.pendingAlerts++
			cmds = append(cmds, bell())
			if r.active != 3 { // not on Alerts: tell the operator how to act, not just that
				cmds = append(cmds, flash("🔔 approval requested — Tab to Alerts, then a approve / d deny"))
			}
		} else if r.pendingAlerts > 0 {
			r.pendingAlerts--
		}
		// forward to the alerts screen wherever we are, and keep listening
		var cmd tea.Cmd
		r.screens[3], cmd = r.screens[3].update(msg)
		cmds = append(cmds, cmd, waitStream(r.stream))
		return r, tea.Batch(cmds...)

	case consentStreamClosedMsg:
		if r.live {
			// stream dropped: try to reopen after a beat — the process may be restarting
			return r, tea.Tick(3*time.Second, func(time.Time) tea.Msg { return reopenStreamMsg{} })
		}
		return r, nil
	case reopenStreamMsg:
		return r, r.openStream()
	}

	var cmd tea.Cmd
	r.screens[r.active], cmd = r.screens[r.active].update(msg)
	return r, cmd
}

type reopenStreamMsg struct{}

// capturer lets a screen tell the root it is in a text-input/modal state and owns all keys.
type capturer interface{ capturing() bool }

func captures(s screen) bool {
	if c, ok := s.(capturer); ok {
		return c.capturing()
	}
	return false
}

func (r *rootModel) View() string {
	if r.width == 0 {
		return "loading…"
	}
	// tab bar
	var tabs []string
	for i, name := range r.tabs {
		label := name
		if name == "Alerts" && r.pendingAlerts > 0 {
			label = name + "(" + itoa(r.pendingAlerts) + ")"
		}
		if i == r.active {
			tabs = append(tabs, styTabActive.Render(label))
		} else {
			tabs = append(tabs, styTab.Render(label))
		}
	}
	mode := r.o.Mode()
	status := styStatusOK.Render("● " + mode)
	if !r.live {
		status = styStatusOff.Render("○ offline — edits apply on next gateway start")
	}
	bar := lipgloss.JoinHorizontal(lipgloss.Center, styBrand.Render(" delegent "), lipgloss.JoinHorizontal(lipgloss.Center, tabs...))
	gap := r.width - lipgloss.Width(bar) - lipgloss.Width(status) - 1
	if gap < 1 {
		gap = 1
	}
	top := bar + lipgloss.NewStyle().Width(gap).Render("") + status
	rule := styRule.Render(strings.Repeat("─", max(1, r.width)))

	// body, height-boxed so the footer stays anchored
	bodyH := r.height - 5
	if bodyH < 3 {
		bodyH = 3
	}
	body := lipgloss.NewStyle().Height(bodyH).MaxHeight(bodyH).Render(r.screens[r.active].view(r.width, bodyH))

	// footer: flash wins over hints
	footer := styDim.Render(" " + r.screens[r.active].hints() + " · tab switch · q quit")
	if r.flash != "" {
		if r.flashErr {
			footer = styErr.Render(" ✗ " + r.flash)
		} else {
			footer = styStatusOK.Render(" ✓ " + r.flash)
		}
	}
	return top + "\n" + rule + "\n" + body + "\n" + rule + "\n" + footer
}
