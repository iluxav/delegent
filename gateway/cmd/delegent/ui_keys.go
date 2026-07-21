package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type keysScreen struct {
	o    ops
	rows []keyRow
	tbl  table.Model

	naming    bool // mint: name prompt active
	nameInput textinput.Model

	confirm string // "", "revoke", "roll" — pending y/n

	picking bool // consent-channel preset picker open for rows[cursor]
	pickIdx int

	// plaintext box: shown once after mint/roll, explicit dismissal required
	plaintext string
	plainName string
}

type keysLoadedMsg struct{ rows []keyRow }
type keyChannelsSavedMsg struct{ name, label string }
type keyMintedMsg struct {
	row       keyRow
	plaintext string
	rolled    bool
}

func newKeysScreen(o ops) *keysScreen {
	ti := textinput.New()
	ti.Placeholder = "key name (e.g. laptop)"
	ti.CharLimit = 48
	ti.Width = 32
	tbl := newListTable([]table.Column{
		{Title: "ID", Width: 24}, {Title: "PREFIX", Width: 10}, {Title: "NAME", Width: 14},
		{Title: "STATE", Width: 8}, {Title: "CONSENT", Width: 16}, {Title: "LAST USED", Width: 14},
	})
	return &keysScreen{o: o, tbl: tbl, nameInput: ti}
}

func (s *keysScreen) sel() *keyRow {
	i := s.tbl.Cursor()
	if i < 0 || i >= len(s.rows) {
		return nil
	}
	return &s.rows[i]
}

func (s *keysScreen) capturing() bool {
	return s.naming || s.confirm != "" || s.plaintext != "" || s.picking
}

// consentPresets mirrors the hosted console's one-click policies: an ordered channel list,
// console always the implicit final fallback. A hand-rolled list reads as "custom".
var consentPresets = []struct {
	label    string
	channels []string
}{
	{"auto", nil},
	{"console only", []string{"console"}},
	{"in-chat first", []string{"elicitation", "console"}},
	{"widget first", []string{"widget", "console"}},
}

func presetLabel(channels []string) string {
	joined := strings.Join(channels, ",")
	for _, pz := range consentPresets {
		if strings.Join(pz.channels, ",") == joined {
			return pz.label
		}
	}
	return "custom: " + joined
}

func (s *keysScreen) init() tea.Cmd { return s.load() }

func (s *keysScreen) load() tea.Cmd {
	return func() tea.Msg {
		rows, err := s.o.ListKeys(context.Background())
		if err != nil {
			return errMsg{err}
		}
		return keysLoadedMsg{rows}
	}
}

func (s *keysScreen) update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case keysLoadedMsg:
		s.rows = msg.rows
		trows := make([]table.Row, 0, len(s.rows))
		for _, k := range s.rows {
			state := "active"
			if k.RevokedAt != 0 {
				state = "REVOKED"
			}
			last := "never"
			if k.LastUsedAt != 0 {
				last = time.UnixMilli(k.LastUsedAt).Format("Jan 02 15:04")
			}
			trows = append(trows, table.Row{k.ID, k.Prefix + "…", k.Name, state, presetLabel(k.ConsentChannels), last})
		}
		s.tbl.SetRows(trows)
		if s.tbl.Cursor() >= len(trows) {
			s.tbl.SetCursor(0)
		}
		return s, nil

	case keyChannelsSavedMsg:
		return s, tea.Batch(flash(msg.name+" consent: "+msg.label), s.load())

	case keyMintedMsg:
		s.plaintext = msg.plaintext
		s.plainName = msg.row.Name
		verb := "minted"
		if msg.rolled {
			verb = "rolled"
		}
		return s, tea.Batch(flash("key "+verb), s.load())

	case tea.KeyMsg:
		// plaintext box swallows everything until explicitly dismissed
		if s.plaintext != "" {
			if msg.String() == "enter" || msg.String() == "esc" {
				s.plaintext = ""
			}
			return s, nil
		}
		if s.naming {
			return s.updateNaming(msg)
		}
		if s.confirm != "" {
			return s.updateConfirm(msg)
		}
		if s.picking {
			return s.updatePicking(msg)
		}
		switch msg.String() {
		case "r":
			return s, s.load()
		case "n":
			s.naming = true
			s.nameInput.SetValue("")
			s.nameInput.Focus()
			return s, textinput.Blink
		case "x":
			if s.active() != nil {
				s.confirm = "revoke"
			}
		case "R":
			if s.active() != nil {
				s.confirm = "roll"
			}
		case "c":
			if s.active() != nil {
				s.picking = true
				s.pickIdx = 0
				cur := strings.Join(s.sel().ConsentChannels, ",")
				for i, pz := range consentPresets {
					if strings.Join(pz.channels, ",") == cur {
						s.pickIdx = i
					}
				}
			}
		default:
			var cmd tea.Cmd
			s.tbl, cmd = s.tbl.Update(msg)
			return s, cmd
		}
	}
	return s, nil
}

// active returns the selected key if it is usable for revoke/roll (not already revoked).
func (s *keysScreen) active() *keyRow {
	k := s.sel()
	if k == nil || k.RevokedAt != 0 {
		return nil
	}
	return k
}

func (s *keysScreen) updateNaming(msg tea.KeyMsg) (screen, tea.Cmd) {
	switch msg.String() {
	case "enter":
		name := strings.TrimSpace(s.nameInput.Value())
		s.naming = false
		if name == "" {
			return s, nil
		}
		return s, func() tea.Msg {
			row, plain, err := s.o.MintKey(context.Background(), name)
			if err != nil {
				return errMsg{err}
			}
			return keyMintedMsg{row: row, plaintext: plain}
		}
	case "esc":
		s.naming = false
		return s, nil
	}
	var cmd tea.Cmd
	s.nameInput, cmd = s.nameInput.Update(msg)
	return s, cmd
}

func (s *keysScreen) updatePicking(msg tea.KeyMsg) (screen, tea.Cmd) {
	switch msg.String() {
	case "esc":
		s.picking = false
	case "up", "k":
		if s.pickIdx > 0 {
			s.pickIdx--
		}
	case "down", "j":
		if s.pickIdx < len(consentPresets)-1 {
			s.pickIdx++
		}
	case "enter":
		s.picking = false
		k := *s.sel()
		channels := consentPresets[s.pickIdx].channels
		label := consentPresets[s.pickIdx].label
		return s, func() tea.Msg {
			if err := s.o.SetKeyChannels(context.Background(), k.ID, channels); err != nil {
				return errMsg{err}
			}
			return keyChannelsSavedMsg{name: k.Name, label: label}
		}
	}
	return s, nil
}

func (s *keysScreen) updateConfirm(msg tea.KeyMsg) (screen, tea.Cmd) {
	verb := s.confirm
	switch msg.String() {
	case "y", "Y":
		s.confirm = ""
		k := *s.sel()
		if verb == "revoke" {
			return s, tea.Sequence(func() tea.Msg {
				if err := s.o.RevokeKey(context.Background(), k.ID); err != nil {
					return errMsg{err}
				}
				return flashMsg{k.ID + " revoked"}
			}, s.load())
		}
		return s, func() tea.Msg {
			row, plain, err := s.o.RollKey(context.Background(), k.ID)
			if err != nil {
				return errMsg{err}
			}
			return keyMintedMsg{row: row, plaintext: plain, rolled: true}
		}
	default:
		s.confirm = ""
	}
	return s, nil
}

func (s *keysScreen) hints() string {
	switch {
	case s.plaintext != "":
		return hintBar(kb("enter", "dismiss (copy it first!)"))
	case s.naming:
		return hintBar(kb("enter", "mint"), kb("esc", "cancel"))
	case s.confirm != "":
		return hintBar(kb("y", "confirm "+s.confirm), kb("esc", "cancel"))
	case s.picking:
		return hintBar(kb("↑↓", "preset"), kb("enter", "set"), kb("esc", "cancel"))
	default:
		return hintBar(kb("↑↓", "select"), kb("n", "new"), kb("R", "roll"), kb("x", "revoke"),
			kb("c", "consent"), kb("r", "reload"))
	}
}

// presetHint explains a preset's channel order; console is always the final fallback.
func presetHint(channels []string) string {
	if len(channels) == 0 {
		return "client's best channel: in-chat dialog, widget, or parked approvals"
	}
	return strings.Join(channels, " → ") + " (console always the final fallback)"
}

func (s *keysScreen) view(width, height int) string {
	if s.plaintext != "" {
		return modal(width, height, fmt.Sprintf(
			"agent key %q — shown ONCE, copy it now:\n\n  %s\n\nupdate your MCP client config, then press enter",
			s.plainName, styBold.Render(s.plaintext)))
	}
	if s.naming {
		return modal(width, height, "mint a new agent key\n\n"+s.nameInput.View()+"\n\n"+styDim.Render("enter mint · esc cancel"))
	}
	if s.confirm != "" {
		k := s.sel()
		return modal(width, height, fmt.Sprintf("%s %s (%s)?\n\n%s", s.confirm, k.ID, k.Name,
			styDim.Render("y confirm · any other key cancels")))
	}
	if s.picking {
		var b strings.Builder
		k := s.sel()
		b.WriteString("consent channel for " + styBold.Render(k.Name) + "\n\n")
		for j, pz := range consentPresets {
			line := padCell(pz.label, 16) + styDim.Render(presetHint(pz.channels))
			if j == s.pickIdx {
				line = styPaneOn.Render(padCell(pz.label, 16)) + styDim.Render(presetHint(pz.channels))
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n" + styDim.Render("↑↓ preset · enter set · esc cancel"))
		return modal(width, height, b.String())
	}

	if len(s.rows) == 0 {
		return styDim.Render("\n  no agent keys — press n to mint one")
	}
	s.tbl.SetWidth(width - 2)
	s.tbl.SetHeight(min(height-1, len(s.rows)+2))
	return "\n" + s.tbl.View()
}
