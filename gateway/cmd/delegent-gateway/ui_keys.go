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

	// plaintext box: shown once after mint/roll, explicit dismissal required
	plaintext string
	plainName string
}

type keysLoadedMsg struct{ rows []keyRow }
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

func (s *keysScreen) capturing() bool { return s.naming || s.confirm != "" || s.plaintext != "" }

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
	default:
		return "↑↓ select · n new · R roll · x revoke · r reload"
	}
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
	b.WriteString(styBold.Render(fmt.Sprintf("  %-24s %-10s %-12s %-9s %s", "ID", "PREFIX", "NAME", "STATE", "LAST USED")) + "\n")
	for i, k := range s.rows {
		state := styStatusOK.Render("active   ")
		if k.RevokedAt != 0 {
			state = styErr.Render("REVOKED  ")
		}
		last := "never"
		if k.LastUsedAt != 0 {
			last = time.UnixMilli(k.LastUsedAt).Format("Jan 02 15:04")
		}
		line := fmt.Sprintf("  %-24s %-10s %-12s %-9s %s", k.ID, k.Prefix+"…", truncate(k.Name, 12), state, last)
		if i == s.cursor {
			line = styCursor.Render(line)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}
