package main

// The dashboard shell: bordered tab row, status line, help-generated footer, global
// consent-alert badge. Each tab is a screen owning its state and keymap; the root routes
// messages, sizes, and the live consent stream. All I/O rides tea.Cmds through the ops
// interface — Update never blocks. Rendering leans on the Charm stack: bubbles/table for
// lists, bubbles/help for footers, lipgloss.Place for modals, bubbles/spinner for waits.

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"delegent.dev/gateway"
)

// --- shared styles ---

var (
	styBrand     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("183"))
	styBadge     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("161")).Padding(0, 1)
	styRule      = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))
	styHead      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("250"))
	styStatusOK  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styStatusOff = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styErr       = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	styDim       = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	styBold      = lipgloss.NewStyle().Bold(true)
	styCursor    = lipgloss.NewStyle().Background(lipgloss.Color("237"))
	styPaneOn    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("57")).Padding(0, 1)
	styRiskHigh  = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	styRiskMed   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styRiskLow   = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styBox       = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2)
	styCardOn    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("57")).Padding(0, 1)
	styCardOff   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("238")).Padding(0, 1)

	// the Charm tabs pattern: rounded tabs whose bottom edge fuses into a baseline rule
	styTabOn = lipgloss.NewStyle().Border(tabBorder("┘", " ", "└"), true).
			BorderForeground(lipgloss.Color("57")).Bold(true).Foreground(lipgloss.Color("183")).Padding(0, 1)
	styTabOff = lipgloss.NewStyle().Border(tabBorder("┴", "─", "┴"), true).
			BorderForeground(lipgloss.Color("238")).Foreground(lipgloss.Color("246")).Padding(0, 1)
)

func tabBorder(left, middle, right string) lipgloss.Border {
	b := lipgloss.RoundedBorder()
	b.BottomLeft, b.Bottom, b.BottomRight = left, middle, right
	return b
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

// --- shared rendering helpers ---

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

// modal centers content in the body area inside an accent-bordered box — the one dialog
// treatment every screen shares (key reveal, confirms, detail views, pickers).
func modal(width, height int, content string) string {
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center,
		styCardOn.Render(content), lipgloss.WithWhitespaceChars(" "))
}

// helpModel renders key.Bindings as footers — the hints can never drift from the actual
// keymap because they ARE the keymap.
var helpModel = help.New()

func hintBar(b ...key.Binding) string {
	return helpModel.ShortHelpView(b)
}

func kb(keys, desc string) key.Binding {
	return key.NewBinding(key.WithKeys(keys), key.WithHelp(keys, desc))
}

// newListTable builds a consistently-styled bubbles table for the list screens.
func newListTable(cols []table.Column) table.Model {
	t := table.New(table.WithColumns(cols), table.WithFocused(true))
	s := table.DefaultStyles()
	s.Header = s.Header.Bold(true).Foreground(lipgloss.Color("250")).
		BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("238")).BorderBottom(true)
	s.Selected = s.Selected.Foreground(lipgloss.Color("15")).Background(lipgloss.Color("57")).Bold(false)
	t.SetStyles(s)
	return t
}

// --- shared messages ---

type errMsg struct{ err error }
type flashMsg struct{ text string }
type consentStreamMsg struct{ ev gateway.ConsentEvent }
type consentStreamClosedMsg struct{}
type clearFlashMsg struct{}
type reopenStreamMsg struct{}
type streamOpenedMsg struct{}

// screen is one tab's model.
type screen interface {
	init() tea.Cmd
	update(msg tea.Msg) (screen, tea.Cmd)
	view(width, height int) string
	hints() string
}

// capturer lets a screen tell the root it is in a text-input/modal state and owns all keys.
type capturer interface{ capturing() bool }

func captures(s screen) bool {
	if c, ok := s.(capturer); ok {
		return c.capturing()
	}
	return false
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
	reconnecting bool
	spin         spinner.Model
}

func newRootModel(o ops) *rootModel {
	r := &rootModel{
		o:    o,
		tabs: []string{"Targets", "Keys", "Audit", "Alerts"},
		live: o.Mode() != "offline",
		spin: spinner.New(spinner.WithSpinner(spinner.Dot)),
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
		return streamOpenedMsg{}
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
		helpModel.Width = msg.Width
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

	case streamOpenedMsg:
		r.reconnecting = false
		return r, waitStream(r.stream)

	case spinner.TickMsg:
		if !r.reconnecting {
			return r, nil // spinner only animates while it is visible
		}
		var cmd tea.Cmd
		r.spin, cmd = r.spin.Update(msg)
		return r, cmd

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
			// stream dropped: show the spinner and retry — the process may be restarting
			r.reconnecting = true
			return r, tea.Batch(r.spin.Tick,
				tea.Tick(3*time.Second, func(time.Time) tea.Msg { return reopenStreamMsg{} }))
		}
		return r, nil
	case reopenStreamMsg:
		return r, r.openStream()
	}

	var cmd tea.Cmd
	r.screens[r.active], cmd = r.screens[r.active].update(msg)
	return r, cmd
}

func (r *rootModel) View() string {
	if r.width == 0 {
		return "loading…"
	}
	// bordered tab row: the active tab's bottom opens into the content; the baseline rule
	// runs under the inactive tabs and extends across to the status text
	var rendered []string
	rendered = append(rendered, styBrand.Render(" delegent "))
	for i, name := range r.tabs {
		label := name
		if name == "Alerts" && r.pendingAlerts > 0 {
			label = name + " " + styBadge.Render(itoa(r.pendingAlerts))
		}
		if i == r.active {
			rendered = append(rendered, styTabOn.Render(label))
		} else {
			rendered = append(rendered, styTabOff.Render(label))
		}
	}
	row := lipgloss.JoinHorizontal(lipgloss.Bottom, rendered...)

	status := styStatusOK.Render("● " + r.o.Mode())
	if r.reconnecting {
		status = styStatusOff.Render(r.spin.View() + "reconnecting…")
	} else if !r.live {
		status = styStatusOff.Render("○ offline — edits apply on next gateway start")
	}
	gap := r.width - lipgloss.Width(row) - lipgloss.Width(status) - 1
	if gap < 1 {
		gap = 1
	}
	base := styRule.Render(strings.Repeat("─", gap))
	top := lipgloss.JoinHorizontal(lipgloss.Bottom, row, base, status+" ")

	bodyH := r.height - lipgloss.Height(top) - 2
	if bodyH < 3 {
		bodyH = 3
	}
	body := lipgloss.NewStyle().Height(bodyH).MaxHeight(bodyH).Render(r.screens[r.active].view(r.width, bodyH))

	// footer: flash wins over hints
	footer := " " + r.screens[r.active].hints() + styDim.Render("  ·  ") + hintBar(kb("tab", "switch"), kb("q", "quit"))
	if r.flash != "" {
		if r.flashErr {
			footer = styErr.Render(" ✗ " + r.flash)
		} else {
			footer = styStatusOK.Render(" ✓ " + r.flash)
		}
	}
	return top + "\n" + body + "\n" + styRule.Render(strings.Repeat("─", r.width)) + "\n" + footer
}
