package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type keysScreen struct {
	o      ops
	rows   []keyRow
	cursor int

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
	return &keysScreen{o: o, nameInput: ti}
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
		if s.cursor >= len(s.rows) {
			s.cursor = 0
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
				cur := strings.Join(s.rows[s.cursor].ConsentChannels, ",")
				for i, pz := range consentPresets {
					if strings.Join(pz.channels, ",") == cur {
						s.pickIdx = i
					}
				}
			}
		}
	}
	return s, nil
}

// active returns the selected key if it is usable for revoke/roll (not already revoked).
func (s *keysScreen) active() *keyRow {
	if len(s.rows) == 0 {
		return nil
	}
	k := s.rows[s.cursor]
	if k.RevokedAt != 0 {
		return nil
	}
	return &k
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
		k := s.rows[s.cursor]
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
		k := s.rows[s.cursor]
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
		return "copy the key, then enter/esc to dismiss"
	case s.naming:
		return "enter mint · esc cancel"
	case s.confirm != "":
		return "y confirm " + s.confirm + " · any other key cancels"
	case s.picking:
		return "↑↓ preset · enter set · esc cancel"
	default:
		return "↑↓ select · n new · R roll · x revoke · c consent · r reload"
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
		return styBox.Render(fmt.Sprintf("agent key %q — shown ONCE, copy it now:\n\n  %s\n\nupdate your MCP client config, then press enter", s.plainName, styBold.Render(s.plaintext)))
	}
	var b strings.Builder
	if s.naming {
		b.WriteString("  mint new key — " + s.nameInput.View() + "\n\n")
	}
	if s.confirm != "" {
		k := s.rows[s.cursor]
		b.WriteString(styStatusOff.Render(fmt.Sprintf("  %s %s (%s)? y/n", s.confirm, k.ID, k.Name)) + "\n\n")
	}
	if len(s.rows) == 0 {
		b.WriteString(styDim.Render("\n  no agent keys — press n to mint one"))
		return b.String()
	}
	b.WriteString("  " + styHead.Render(padCell("ID", 24)+" "+padCell("PREFIX", 10)+" "+padCell("NAME", 12)+" "+padCell("STATE", 8)+" "+padCell("CONSENT", 16)+" "+"LAST USED") + "\n")
	for i, k := range s.rows {
		state, stateSty := "active", styStatusOK
		if k.RevokedAt != 0 {
			state, stateSty = "REVOKED", styErr
		}
		last := "never"
		if k.LastUsedAt != 0 {
			last = time.UnixMilli(k.LastUsedAt).Format("Jan 02 15:04")
		}
		plainCells := padCell(k.ID, 24) + " " + padCell(k.Prefix+"…", 10) + " " + padCell(k.Name, 12)
		line := plainCells + " " + stateSty.Render(padCell(state, 8)) + " " + padCell(presetLabel(k.ConsentChannels), 16) + " " + last
		if i == s.cursor {
			line = styCursor.Render(plainCells + " " + padCell(state, 8) + " " + padCell(presetLabel(k.ConsentChannels), 16) + " " + last)
		}
		b.WriteString("  " + line + "\n")
		if s.picking && i == s.cursor {
			for j, pz := range consentPresets {
				mark := "  "
				if j == s.pickIdx {
					mark = "▸ "
				}
				row := fmt.Sprintf("      %s%-14s %s", mark, pz.label, styDim.Render(presetHint(pz.channels)))
				if j == s.pickIdx {
					row = styCursor.Render(row)
				}
				b.WriteString(row + "\n")
			}
		}
	}
	return b.String()
}
