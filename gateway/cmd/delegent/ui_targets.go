package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"delegent.dev/gateway/introspect"
	"delegent.dev/gateway/provision"
)

// effectCycle is the order the 'e' key steps a tool's effect through.
var effectCycle = []string{"read", "write", "destructive", "external", "spends", "unknown"}

type targetsScreen struct {
	o ops

	// list mode
	rows   []targetRow
	cursor int

	// detail mode
	detail     *targetDetail
	inDetail   bool
	pane       int // 0 = policy, 1 = scopes
	toolCursor int
	tools      []provision.ToolSpec // working copy; dirty until saved
	newTools   map[string]bool      // names merged from re-introspection
	dirty      bool
	scopeRows  []scopeRowView
	scopeCur   int

	editing   bool // scope text edit on the policy row under the cursor
	scopeEdit textinput.Model
}

type scopeRowView struct {
	scope, human, risk string
	disabled           bool
}

type targetsLoadedMsg struct{ rows []targetRow }
type targetDetailMsg struct{ d *targetDetail }
type policySavedMsg struct{}
type entUpdatedMsg struct{ ent *entitlementView }
type introspectedMsg struct{ res *introspect.Result }

func newTargetsScreen(o ops) *targetsScreen {
	ti := textinput.New()
	ti.CharLimit = 64
	ti.Width = 24
	return &targetsScreen{o: o, scopeEdit: ti, newTools: map[string]bool{}}
}

func (s *targetsScreen) capturing() bool { return s.editing }

func (s *targetsScreen) init() tea.Cmd { return s.loadList() }

func (s *targetsScreen) loadList() tea.Cmd {
	return func() tea.Msg {
		rows, err := s.o.ListTargets(context.Background())
		if err != nil {
			return errMsg{err}
		}
		return targetsLoadedMsg{rows}
	}
}

func (s *targetsScreen) loadDetail(id string) tea.Cmd {
	return func() tea.Msg {
		d, err := s.o.TargetDetail(context.Background(), id)
		if err != nil {
			return errMsg{err}
		}
		return targetDetailMsg{d}
	}
}

func (s *targetsScreen) update(msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case targetsLoadedMsg:
		s.rows = msg.rows
		if s.cursor >= len(s.rows) {
			s.cursor = 0
		}
		return s, nil

	case targetDetailMsg:
		s.detail = msg.d
		s.inDetail = true
		s.tools = append([]provision.ToolSpec(nil), msg.d.Tools...)
		s.newTools = map[string]bool{}
		s.dirty = false
		s.toolCursor, s.scopeCur, s.pane = 0, 0, 0
		s.rebuildScopeRows()
		return s, nil

	case policySavedMsg:
		s.dirty = false
		return s, tea.Batch(flash("policy saved"), s.loadDetail(s.detail.Target.ID))

	case entUpdatedMsg:
		if s.detail != nil {
			s.detail.Entitlement = *msg.ent
			s.rebuildScopeRows()
		}
		return s, flash("scopes updated")

	case introspectedMsg:
		known := map[string]bool{}
		for _, tl := range s.tools {
			known[tl.Name] = true
		}
		added := 0
		for _, d := range msg.res.Tools {
			if known[d.Name] {
				continue
			}
			s.tools = append(s.tools, provision.ToolSpec{Name: d.Name, Effect: d.Effect, Scope: d.Scope, Semantics: d.Semantics, Description: d.Description})
			s.newTools[d.Name] = true
			added++
		}
		if added > 0 {
			s.dirty = true
			return s, flash(fmt.Sprintf("%d new tool(s) drafted — review and save", added))
		}
		return s, flash("no new tools upstream")

	case tea.KeyMsg:
		if s.editing {
			return s.updateScopeEdit(msg)
		}
		if s.inDetail {
			return s.updateDetail(msg)
		}
		return s.updateList(msg)
	}
	return s, nil
}

func (s *targetsScreen) updateList(msg tea.KeyMsg) (screen, tea.Cmd) {
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
		return s, s.loadList()
	case "enter":
		if len(s.rows) > 0 {
			return s, s.loadDetail(s.rows[s.cursor].ID)
		}
	case "e":
		if len(s.rows) > 0 {
			row := s.rows[s.cursor]
			return s, tea.Sequence(func() tea.Msg {
				if err := s.o.SetTargetEnabled(context.Background(), row.ID, !row.Enabled); err != nil {
					return errMsg{err}
				}
				return flashMsg{row.ID + " toggled"}
			}, s.loadList())
		}
	}
	return s, nil
}

func (s *targetsScreen) updateDetail(msg tea.KeyMsg) (screen, tea.Cmd) {
	switch msg.String() {
	case "esc":
		s.inDetail = false
		return s, s.loadList()
	case "left", "right":
		s.pane = 1 - s.pane
		return s, nil
	case "I":
		id := s.detail.Target.ID
		return s, tea.Batch(flash("introspecting upstream…"), func() tea.Msg {
			res, err := s.o.Introspect(context.Background(), id)
			if err != nil {
				return errMsg{err}
			}
			return introspectedMsg{res}
		})
	}
	if s.pane == 0 {
		return s.updatePolicyPane(msg)
	}
	return s.updateScopesPane(msg)
}

func (s *targetsScreen) updatePolicyPane(msg tea.KeyMsg) (screen, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if s.toolCursor > 0 {
			s.toolCursor--
		}
	case "down", "j":
		if s.toolCursor < len(s.tools)-1 {
			s.toolCursor++
		}
	case "e": // cycle effect
		if len(s.tools) > 0 {
			t := &s.tools[s.toolCursor]
			next := 0
			for i, eff := range effectCycle {
				if eff == t.Effect {
					next = (i + 1) % len(effectCycle)
					break
				}
			}
			t.Effect = effectCycle[next]
			if t.Effect == "unknown" {
				t.Scope = ""
			} else if t.Scope == "" {
				t.Scope = t.Name + ":" + t.Effect
			}
			s.dirty = true
		}
	case "u": // unknown = refused
		if len(s.tools) > 0 {
			s.tools[s.toolCursor].Effect = "unknown"
			s.tools[s.toolCursor].Scope = ""
			s.dirty = true
		}
	case "enter": // edit scope
		if len(s.tools) > 0 && s.tools[s.toolCursor].Effect != "unknown" && s.tools[s.toolCursor].Effect != "" {
			s.editing = true
			s.scopeEdit.SetValue(s.tools[s.toolCursor].Scope)
			s.scopeEdit.Focus()
			return s, textinput.Blink
		}
	case "s": // save
		return s.savePolicy()
	}
	return s, nil
}

func (s *targetsScreen) savePolicy() (screen, tea.Cmd) {
	if !s.dirty {
		return s, flash("nothing to save")
	}
	id, tools := s.detail.Target.ID, append([]provision.ToolSpec(nil), s.tools...)
	return s, func() tea.Msg {
		if err := s.o.PutPolicy(context.Background(), id, "", tools); err != nil {
			return errMsg{err}
		}
		return policySavedMsg{}
	}
}

func (s *targetsScreen) updateScopeEdit(msg tea.KeyMsg) (screen, tea.Cmd) {
	switch msg.String() {
	case "enter":
		v := strings.TrimSpace(s.scopeEdit.Value())
		if v != "" {
			s.tools[s.toolCursor].Scope = v
			s.dirty = true
		}
		s.editing = false
		return s, nil
	case "esc":
		s.editing = false
		return s, nil
	}
	var cmd tea.Cmd
	s.scopeEdit, cmd = s.scopeEdit.Update(msg)
	return s, cmd
}

func (s *targetsScreen) updateScopesPane(msg tea.KeyMsg) (screen, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if s.scopeCur > 0 {
			s.scopeCur--
		}
	case "down", "j":
		if s.scopeCur < len(s.scopeRows)-1 {
			s.scopeCur++
		}
	case "e": // scope-centric bulk effect cycle across the scope's tools
		if len(s.scopeRows) > 0 {
			if !s.cycleScopeEffect(s.scopeRows[s.scopeCur].scope) {
				return s, flash("no classified tools behind this scope")
			}
		}
		return s, nil
	case "s":
		return s.savePolicy()
	case " ": // toggle opt-out and persist immediately
		if len(s.scopeRows) == 0 {
			return s, nil
		}
		s.scopeRows[s.scopeCur].disabled = !s.scopeRows[s.scopeCur].disabled
		var disabled []string
		for _, r := range s.scopeRows {
			if r.disabled {
				disabled = append(disabled, r.scope)
			}
		}
		id := s.detail.Target.ID
		return s, func() tea.Msg {
			ent, err := s.o.SetDisabled(context.Background(), id, disabled)
			if err != nil {
				return errMsg{err}
			}
			return entUpdatedMsg{ent}
		}
	}
	return s, nil
}

// scopeEffect returns the strongest effect among working tools requiring scope ("" = no tools).
func (s *targetsScreen) scopeEffect(scope string) string {
	eff := ""
	for _, tl := range s.tools {
		if tl.Scope == scope && !provision.IsUnknown(tl.Effect) && provision.Rank(tl.Effect) > provision.Rank(eff) {
			eff = tl.Effect
		}
	}
	return eff
}

// cycleScopeEffect steps EVERY tool requiring scope to the next effect after the current
// dominant one — the scope-centric bulk edit. Marks the policy dirty; 's' saves.
func (s *targetsScreen) cycleScopeEffect(scope string) bool {
	cur := s.scopeEffect(scope)
	if cur == "" {
		return false // no classified tools behind this scope (e.g. mcp:connect)
	}
	next := effectCycle[0]
	for i, eff := range effectCycle {
		if eff == cur {
			next = effectCycle[(i+1)%len(effectCycle)]
			break
		}
	}
	changed := false
	for i := range s.tools {
		if s.tools[i].Scope == scope {
			s.tools[i].Effect = next
			changed = true
		}
	}
	if changed {
		s.dirty = true
	}
	return changed
}

func (s *targetsScreen) rebuildScopeRows() {
	off := map[string]bool{}
	for _, sc := range s.detail.Entitlement.Disabled {
		off[sc] = true
	}
	doc := map[string]provision.ScopeDoc{}
	for _, d := range s.detail.ScopeDocs {
		doc[d.Scope] = d
	}
	s.scopeRows = s.scopeRows[:0]
	for _, sc := range s.detail.Entitlement.Scopes {
		row := scopeRowView{scope: sc, disabled: off[sc], human: doc[sc].Human, risk: doc[sc].Risk}
		if row.risk == "" {
			row.risk = "medium"
		}
		s.scopeRows = append(s.scopeRows, row)
	}
	if s.scopeCur >= len(s.scopeRows) {
		s.scopeCur = 0
	}
}

func (s *targetsScreen) hints() string {
	switch {
	case s.editing:
		return "enter set scope · esc cancel"
	case s.inDetail && s.pane == 0:
		return "↑↓ tool · e effect · enter scope · u refuse · I re-introspect · s save · ←→ scopes pane · esc back"
	case s.inDetail:
		return "↑↓ scope · space opt-in/out · e cycle tools' effect · s save · ←→ policy pane · esc back"
	default:
		return "↑↓ select · enter open · e enable/disable · r reload"
	}
}

func (s *targetsScreen) view(width, height int) string {
	if s.inDetail && s.detail != nil {
		return s.viewDetail(width, height)
	}
	if len(s.rows) == 0 {
		return styDim.Render("\n  no targets — add one with 'delegent target add'")
	}
	var b strings.Builder
	b.WriteString(styBold.Render(fmt.Sprintf("  %-16s %-9s %-6s %-14s %s", "TARGET", "STATE", "TOOLS", "CREDENTIAL", "ENDPOINT")) + "\n")
	for i, r := range s.rows {
		state := styStatusOK.Render("enabled ")
		if !r.Enabled {
			state = styStatusOff.Render("DISABLED")
		}
		line := fmt.Sprintf("  %-16s %-9s %-6d %-14s %s", r.ID, state, r.Tools, r.CredentialKind, r.Endpoint)
		if i == s.cursor {
			line = styCursor.Render(line)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func (s *targetsScreen) viewDetail(width, height int) string {
	d := s.detail
	var b strings.Builder
	title := fmt.Sprintf("  %s (%s) — %s", styBold.Render(d.Target.ID), d.Target.Name, d.Target.Endpoint)
	if s.dirty {
		title += styStatusOff.Render("  [unsaved]")
	}
	b.WriteString(title + "\n\n")

	paneNames := []string{"Tool policy", "Operator entitlement"}
	for i, n := range paneNames {
		if i == s.pane {
			b.WriteString(styTabActive.Render(n))
		} else {
			b.WriteString(styTab.Render(n))
		}
	}
	b.WriteString("\n\n")

	if s.pane == 0 {
		b.WriteString(styBold.Render(fmt.Sprintf("  %-28s %-12s %-22s %s", "TOOL", "EFFECT", "SCOPE", "")) + "\n")
		for i, t := range s.tools {
			eff := t.Effect
			if provision.IsUnknown(eff) {
				eff = styErr.Render("unknown→deny")
			}
			mark := ""
			if s.newTools[t.Name] {
				mark = styStatusOK.Render(" NEW")
			}
			line := fmt.Sprintf("  %-28s %-12s %-22s%s", truncate(t.Name, 28), eff, t.Scope, mark)
			if i == s.toolCursor {
				line = styCursor.Render(line)
				if s.editing {
					line = fmt.Sprintf("  %-28s %-12s %s", truncate(t.Name, 28), t.Effect, s.scopeEdit.View())
				}
			}
			b.WriteString(line + "\n")
		}
	} else {
		b.WriteString(styDim.Render("  the operator's entitlement on this target — what grants may draw from") + "\n\n")
		for i, r := range s.scopeRows {
			box := "[x]"
			note := ""
			if r.disabled {
				box = "[ ]"
				note = styDim.Render("  (opted out)")
			}
			eff := s.scopeEffect(r.scope)
			if eff == "" {
				eff = "—"
			}
			line := fmt.Sprintf("  %s %-24s %-12s %s %s%s", box, r.scope, eff, riskStyle(r.risk).Render(fmt.Sprintf("%-7s", r.risk)), styDim.Render(truncate(r.human, 38)), note)
			if i == s.scopeCur {
				line = styCursor.Render(line)
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n" + styDim.Render("  effective: "+strings.Join(s.detail.Entitlement.Effective, " ")) + "\n")
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

var _ = lipgloss.Width // keep lipgloss referenced even if styles change
