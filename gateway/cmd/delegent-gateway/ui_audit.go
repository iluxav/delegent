package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"delegent.dev/gateway/store"
)

type auditScreen struct {
	o    ops
	live bool

	events []*store.Event
	cursor int

	filtering bool
	filter    textinput.Model
	query     string

	expanded bool
}

type eventsLoadedMsg struct{ events []*store.Event }
type auditTickMsg struct{}

func newAuditScreen(o ops, live bool) *auditScreen {
	ti := textinput.New()
	ti.Placeholder = "filter: key, target, tool, type, or decision"
	ti.CharLimit = 48
	ti.Width = 40
	return &auditScreen{o: o, live: live, filter: ti}
}

func (s *auditScreen) capturing() bool { return s.filtering || s.expanded }

func (s *auditScreen) init() tea.Cmd {
	cmds := []tea.Cmd{s.load()}
	if s.live {
		cmds = append(cmds, s.tick())
	}
	return tea.Batch(cmds...)
}

func (s *auditScreen) tick() tea.Cmd {
	return tea.Tick(3*time.Second, func(time.Time) tea.Msg { return auditTickMsg{} })
}

func (s *auditScreen) load() tea.Cmd {
	return func() tea.Msg {
		events, err := s.o.ListEvents(context.Background(), store.EventFilter{Limit: 500})
		if err != nil {
			return errMsg{err}
		}
		return eventsLoadedMsg{events}
	}
}

// visible applies the client-side filter across the fields a human greps by.
func (s *auditScreen) visible() []*store.Event {
	if s.query == "" {
		return s.events
	}
	q := strings.ToLower(s.query)
	var out []*store.Event
	for _, e := range s.events {
		hay := strings.ToLower(strings.Join([]string{e.KeyName, e.TargetID, e.Tool, e.Type, e.Decision, e.AgentName}, " "))
		if strings.Contains(hay, q) {
			out = append(out, e)
		}
	}
	return out
}

func (s *auditScreen) update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case eventsLoadedMsg:
		s.events = msg.events
		if s.cursor >= len(s.visible()) {
			s.cursor = 0
		}
		return s, nil

	case auditTickMsg:
		// live tail via cheap re-list; the tick chain stops the moment live mode ends
		if s.live {
			return s, tea.Batch(s.load(), s.tick())
		}
		return s, nil

	case tea.KeyMsg:
		if s.filtering {
			switch msg.String() {
			case "enter":
				s.query = strings.TrimSpace(s.filter.Value())
				s.filtering = false
				s.cursor = 0
			case "esc":
				s.filtering = false
			default:
				var cmd tea.Cmd
				s.filter, cmd = s.filter.Update(msg)
				return s, cmd
			}
			return s, nil
		}
		if s.expanded {
			if msg.String() == "enter" || msg.String() == "esc" {
				s.expanded = false
			}
			return s, nil
		}
		switch msg.String() {
		case "up", "k":
			if s.cursor > 0 {
				s.cursor--
			}
		case "down", "j":
			if s.cursor < len(s.visible())-1 {
				s.cursor++
			}
		case "/":
			s.filtering = true
			s.filter.SetValue(s.query)
			s.filter.Focus()
			return s, textinput.Blink
		case "c":
			s.query = ""
			s.cursor = 0
		case "r":
			return s, s.load()
		case "enter":
			if len(s.visible()) > 0 {
				s.expanded = true
			}
		}
	}
	return s, nil
}

func (s *auditScreen) hints() string {
	switch {
	case s.filtering:
		return "enter apply · esc cancel"
	case s.expanded:
		return "enter/esc close"
	default:
		return "↑↓ select · enter detail · / filter · c clear · r reload"
	}
}

func (s *auditScreen) view(width, height int) string {
	rows := s.visible()
	if s.expanded && s.cursor < len(rows) {
		return s.viewExpanded(rows[s.cursor])
	}
	var b strings.Builder
	if s.filtering {
		b.WriteString("  " + s.filter.View() + "\n\n")
	} else if s.query != "" {
		b.WriteString(styDim.Render("  filter: "+s.query+" (c to clear)") + "\n\n")
	}
	if len(rows) == 0 {
		b.WriteString(styDim.Render("\n  no events yet"))
		return b.String()
	}
	b.WriteString(styBold.Render(fmt.Sprintf("  %-12s %-20s %-10s %-14s %-24s %s", "TIME", "TYPE", "KEY", "TARGET", "TOOL", "DECISION")) + "\n")
	max := height - 4
	if max < 3 {
		max = 3
	}
	for i, e := range rows {
		if i >= max {
			b.WriteString(styDim.Render(fmt.Sprintf("  … %d more (filter to narrow)", len(rows)-max)) + "\n")
			break
		}
		ts := time.UnixMilli(e.CreatedAt).Format("Jan02 15:04:05")
		dec := e.Decision
		if dec == "deny" || e.Type == store.EventPermissionDenied || e.Type == store.EventError {
			dec = styErr.Render(dec + " " + e.Type)
		}
		line := fmt.Sprintf("  %-12s %-20s %-10s %-14s %-24s %s", ts, e.Type, truncate(e.KeyName, 10), truncate(e.TargetID, 14), truncate(e.Tool, 24), dec)
		if i == s.cursor {
			line = styCursor.Render(line)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func (s *auditScreen) viewExpanded(e *store.Event) string {
	pretty := func(raw json.RawMessage) string {
		if len(raw) == 0 {
			return styDim.Render("(none)")
		}
		var v any
		if json.Unmarshal(raw, &v) == nil {
			if out, err := json.MarshalIndent(v, "  ", "  "); err == nil {
				return truncate(string(out), 1500)
			}
		}
		return truncate(string(raw), 1500)
	}
	body := fmt.Sprintf("%s  %s\n\nkey: %s (%s…)   target: %s   tool: %s\nagent: %s   decision: %s   client: %s %s   ip: %s",
		time.UnixMilli(e.CreatedAt).Format(time.RFC3339), styBold.Render(e.Type),
		e.KeyName, e.KeyPrefix, e.TargetID, e.Tool, e.AgentName, e.Decision, e.ClientName, e.ClientVersion, e.RemoteIP)
	if e.Intent != "" {
		body += "\nintent: " + e.Intent
	}
	if e.Reason != "" {
		body += "\nreason: " + e.Reason
	}
	if e.Error != "" {
		body += "\n" + styErr.Render("error: "+e.Error)
	}
	body += "\n\nparams:\n  " + pretty(e.Params) + "\n\nresult:\n  " + pretty(e.Result)
	return styBox.Render(body)
}
