package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/table"
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
	rows []targetRow
	tbl  table.Model

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
	tbl := newListTable([]table.Column{
		{Title: "TARGET", Width: 16}, {Title: "STATE", Width: 8}, {Title: "TOOLS", Width: 5},
		{Title: "CREDENTIAL", Width: 12}, {Title: "ENDPOINT", Width: 40},
	})
	return &targetsScreen{o: o, tbl: tbl, scopeEdit: ti, newTools: map[string]bool{}}
}

// sel returns the target under the table cursor.
func (s *targetsScreen) sel() *targetRow {
	i := s.tbl.Cursor()
	if i < 0 || i >= len(s.rows) {
		return nil
	}
	return &s.rows[i]
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
		trows := make([]table.Row, 0, len(s.rows))
		for _, r := range s.rows {
			state := "enabled"
			if !r.Enabled {
				state = "DISABLED"
			}
			trows = append(trows, table.Row{r.ID, state, itoa(r.Tools), r.CredentialKind, r.Endpoint})
		}
		s.tbl.SetRows(trows)
		if s.tbl.Cursor() >= len(trows) {
			s.tbl.SetCursor(0)
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
	case "r":
		return s, s.loadList()
	case "enter":
		if row := s.sel(); row != nil {
			return s, s.loadDetail(row.ID)
		}
	case "e":
		if row := s.sel(); row != nil {
			id, enabled := row.ID, row.Enabled
			return s, tea.Sequence(func() tea.Msg {
				if err := s.o.SetTargetEnabled(context.Background(), id, !enabled); err != nil {
					return errMsg{err}
				}
				return flashMsg{id + " toggled"}
			}, s.loadList())
		}
	default: // navigation (arrows, j/k, paging) belongs to the table
		var cmd tea.Cmd
		s.tbl, cmd = s.tbl.Update(msg)
		return s, cmd
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
		return hintBar(kb("enter", "set scope"), kb("esc", "cancel"))
	case s.inDetail && s.pane == 0:
		return hintBar(kb("↑↓", "tool"), kb("e", "effect"), kb("enter", "scope"), kb("u", "refuse"),
			kb("I", "re-introspect"), kb("s", "save"), kb("←→", "entitlement pane"), kb("esc", "back"))
	case s.inDetail:
		return hintBar(kb("↑↓", "scope"), kb("space", "opt-in/out"), kb("e", "cycle effect"),
			kb("s", "save"), kb("←→", "policy pane"), kb("esc", "back"))
	default:
		return hintBar(kb("↑↓", "select"), kb("enter", "open"), kb("e", "enable/disable"), kb("r", "reload"))
	}
}

func (s *targetsScreen) view(width, height int) string {
	if s.inDetail && s.detail != nil {
		return s.viewDetail(width, height)
	}
	if len(s.rows) == 0 {
		return styDim.Render("\n  no targets — add one with 'delegent target add'")
	}
	endpointW := width - 55
	if endpointW < 16 {
		endpointW = 16
	}
	s.tbl.SetColumns([]table.Column{
		{Title: "TARGET", Width: 16}, {Title: "STATE", Width: 8}, {Title: "TOOLS", Width: 5},
		{Title: "CREDENTIAL", Width: 12}, {Title: "ENDPOINT", Width: endpointW},
	})
	s.tbl.SetWidth(width - 2)
	s.tbl.SetHeight(min(height-1, len(s.rows)+2))
	return "\n" + s.tbl.View()
}

// window returns the [start,end) slice bounds that keep cursor visible in a viewport of
// size visible, biased to keep the cursor centered while clamping at the edges.
func window(cursor, total, visible int) (int, int) {
	if visible >= total || visible <= 0 {
		return 0, total
	}
	start := cursor - visible/2
	if start < 0 {
		start = 0
	}
	if start+visible > total {
		start = total - visible
	}
	return start, start + visible
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
			b.WriteString(styPaneOn.Render(n))
		} else {
			b.WriteString(styDim.Render("  " + n + "  "))
		}
	}
	b.WriteString("\n\n")

	if s.pane == 0 {
		b.WriteString("  " + styHead.Render(padCell("TOOL", 28)+" "+padCell("EFFECT", 12)+" "+"SCOPE") + "\n")
		visible := height - 8 // title, pane row, header, scroll indicators, padding
		if visible < 5 {
			visible = 5
		}
		start, end := window(s.toolCursor, len(s.tools), visible)
		if start > 0 {
			b.WriteString(styDim.Render(fmt.Sprintf("  ↑ %d more above", start)) + "\n")
		}
		for i, t := range s.tools {
			if i < start || i >= end {
				continue
			}
			eff, effSty := t.Effect, styDim
			if provision.IsUnknown(eff) {
				eff, effSty = "unknown→deny", styErr
			}
			mark := ""
			if s.newTools[t.Name] {
				mark = " " + styStatusOK.Render("NEW")
			}
			line := padCell(t.Name, 28) + " " + effSty.Render(padCell(eff, 12)) + " " + padCell(t.Scope, 22) + mark
			if i == s.toolCursor {
				if s.editing {
					line = styCursor.Render(padCell(t.Name, 28)+" "+padCell(t.Effect, 12)) + " " + s.scopeEdit.View()
				} else {
					line = styCursor.Render(padCell(t.Name, 28)+" "+padCell(eff, 12)+" "+padCell(t.Scope, 22)) + mark
				}
			}
			b.WriteString("  " + line + "\n")
		}
		if end < len(s.tools) {
			b.WriteString(styDim.Render(fmt.Sprintf("  ↓ %d more below", len(s.tools)-end)) + "\n")
		}
	} else {
		b.WriteString(styDim.Render("  the operator's entitlement on this target — what grants may draw from") + "\n\n")
		visible := height - 9
		if visible < 5 {
			visible = 5
		}
		start, end := window(s.scopeCur, len(s.scopeRows), visible)
		if start > 0 {
			b.WriteString(styDim.Render(fmt.Sprintf("  ↑ %d more above", start)) + "\n")
		}
		for i, r := range s.scopeRows {
			if i < start || i >= end {
				continue
			}
			box := "[x]"
			note := ""
			if r.disabled {
				box = "[ ]"
				note = "  " + styDim.Render("(opted out)")
			}
			eff := s.scopeEffect(r.scope)
			if eff == "" {
				eff = "—"
			}
			plain := box + " " + padCell(r.scope, 24) + " " + padCell(eff, 12)
			line := plain + " " + riskStyle(r.risk).Render(padCell(r.risk, 7)) + " " + styDim.Render(truncate(r.human, 38)) + note
			if i == s.scopeCur {
				line = styCursor.Render(plain+" "+padCell(r.risk, 7)) + " " + styDim.Render(truncate(r.human, 38)) + note
			}
			b.WriteString("  " + line + "\n")
		}
		if end < len(s.scopeRows) {
			b.WriteString(styDim.Render(fmt.Sprintf("  ↓ %d more below", len(s.scopeRows)-end)) + "\n")
		}
		b.WriteString("\n" + styDim.Render("  effective: "+truncate(strings.Join(s.detail.Entitlement.Effective, " "), width-14)) + "\n")
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
