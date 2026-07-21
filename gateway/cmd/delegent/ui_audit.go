package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"delegent.dev/gateway/store"
)

type auditScreen struct {
	o    ops
	live bool

	events []*store.Event
	tbl    table.Model

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
	tbl := newListTable([]table.Column{
		{Title: "TIME", Width: 14}, {Title: "TYPE", Width: 20}, {Title: "KEY", Width: 10},
		{Title: "TARGET", Width: 14}, {Title: "TOOL", Width: 24}, {Title: "DECISION", Width: 10},
	})
	return &auditScreen{o: o, live: live, tbl: tbl, filter: ti}
}

// syncRows mirrors the current visible events into the table, keeping the cursor sane.
func (s *auditScreen) syncRows() {
	rows := s.visible()
	trows := make([]table.Row, 0, len(rows))
	for _, e := range rows {
		trows = append(trows, table.Row{
			time.UnixMilli(e.CreatedAt).Format("Jan02 15:04:05"), e.Type,
			e.KeyName, e.TargetID, e.Tool, e.Decision,
		})
	}
	s.tbl.SetRows(trows)
	if len(trows) > 0 && (s.tbl.Cursor() < 0 || s.tbl.Cursor() >= len(trows)) {
		s.tbl.SetCursor(0)
	}
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
		s.syncRows()
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
				s.tbl.SetCursor(0)
				s.syncRows()
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
		case "/":
			s.filtering = true
			s.filter.SetValue(s.query)
			s.filter.Focus()
			return s, textinput.Blink
		case "c":
			s.query = ""
			s.tbl.SetCursor(0)
			s.syncRows()
		case "r":
			return s, s.load()
		case "enter":
			if len(s.visible()) > 0 {
				s.expanded = true
			}
		default:
			var cmd tea.Cmd
			s.tbl, cmd = s.tbl.Update(msg)
			return s, cmd
		}
	}
	return s, nil
}

func (s *auditScreen) hints() string {
	switch {
	case s.filtering:
		return hintBar(kb("enter", "apply"), kb("esc", "cancel"))
	case s.expanded:
		return hintBar(kb("esc", "close"))
	default:
		return hintBar(kb("↑↓", "select"), kb("enter", "detail"), kb("/", "filter"), kb("c", "clear"), kb("r", "reload"))
	}
}

func (s *auditScreen) view(width, height int) string {
	rows := s.visible()
	if s.expanded && s.tbl.Cursor() < len(rows) {
		return modal(width, height, s.viewExpanded(rows[s.tbl.Cursor()]))
	}
	var b strings.Builder
	if s.filtering {
		b.WriteString("  " + s.filter.View() + "\n")
	} else if s.query != "" {
		b.WriteString(styDim.Render("  filter: "+s.query+" (c to clear)") + "\n")
	}
	if len(rows) == 0 {
		b.WriteString(styDim.Render("\n  no events yet"))
		return b.String()
	}
	s.tbl.SetWidth(width - 2)
	s.tbl.SetHeight(min(height-2, len(rows)+2))
	b.WriteString(s.tbl.View())
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
	return body
}
