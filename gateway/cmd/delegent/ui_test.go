package main

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"delegent.dev/gateway"
	"delegent.dev/gateway/introspect"
	"delegent.dev/gateway/provision"
	"delegent.dev/gateway/store"
)

// fakeOps records mutations; reads serve canned data. Screens are plain Update functions, so
// driving them is: feed a msg, run returned cmds synchronously, assert state.
type fakeOps struct {
	resolved     []string
	resolveOK    bool
	disabledSet  [][]string
	mintedNames  []string
	channelSets  []string
	rolledIDs    []string
	consents     consentBundle
	streamCh     chan gateway.ConsentEvent
	streamCancel bool
}

func (f *fakeOps) Mode() string { return "live: fake pid 1" }
func (f *fakeOps) Close() error { return nil }
func (f *fakeOps) ListTargets(context.Context) ([]targetRow, error) {
	return []targetRow{{ID: "gh", Name: "github", Enabled: true, Tools: 2}}, nil
}
func (f *fakeOps) TargetDetail(context.Context, string) (*targetDetail, error) {
	return &targetDetail{
		Target: targetRow{ID: "gh", Name: "github", Enabled: true},
		Tools: []provision.ToolSpec{
			{Name: "read_file", Effect: "read", Scope: "files:read"},
			{Name: "send_mail", Effect: "external", Scope: "mail:send"},
		},
		ScopeDocs: []provision.ScopeDoc{{Scope: "files:read", Human: "Read files", Risk: "low"}, {Scope: "mail:send", Human: "Send mail", Risk: "high"}},
		Entitlement: entitlementView{
			Scopes: []string{"files:read", "mail:send", "mcp:connect"}, Effective: []string{"files:read", "mail:send", "mcp:connect"},
		},
	}, nil
}
func (f *fakeOps) PutPolicy(context.Context, string, string, []provision.ToolSpec) error { return nil }
func (f *fakeOps) SetTargetEnabled(context.Context, string, bool) error                  { return nil }
func (f *fakeOps) Introspect(context.Context, string) (*introspect.Result, error) {
	return &introspect.Result{Tools: []introspect.DraftTool{{Name: "new_tool", Effect: "read", Scope: "new:read"}}}, nil
}
func (f *fakeOps) SetDisabled(_ context.Context, _ string, disabled []string) (*entitlementView, error) {
	f.disabledSet = append(f.disabledSet, disabled)
	return &entitlementView{Scopes: []string{"files:read", "mail:send", "mcp:connect"}, Disabled: disabled, Effective: []string{"files:read", "mcp:connect"}}, nil
}
func (f *fakeOps) ListKeys(context.Context) ([]keyRow, error) {
	return []keyRow{{ID: "akey_1", Prefix: "dgk_ab", Name: "laptop"}}, nil
}
func (f *fakeOps) MintKey(_ context.Context, name string) (keyRow, string, error) {
	f.mintedNames = append(f.mintedNames, name)
	return keyRow{ID: "akey_new", Name: name}, "dgk_plaintext", nil
}
func (f *fakeOps) RevokeKey(context.Context, string) error { return nil }
func (f *fakeOps) SetKeyChannels(_ context.Context, id string, channels []string) error {
	f.channelSets = append(f.channelSets, id+"="+strings.Join(channels, ","))
	return nil
}
func (f *fakeOps) RollKey(_ context.Context, id string) (keyRow, string, error) {
	f.rolledIDs = append(f.rolledIDs, id)
	return keyRow{ID: "akey_next", Name: "laptop"}, "dgk_rolled", nil
}
func (f *fakeOps) ListEvents(context.Context, store.EventFilter) ([]*store.Event, error) {
	return []*store.Event{{ID: "evt_1", Type: store.EventToolCall, KeyName: "laptop", TargetID: "gh", Tool: "read_file", Decision: "grant", CreatedAt: 1000}}, nil
}
func (f *fakeOps) Consents(context.Context) (*consentBundle, error) { return &f.consents, nil }
func (f *fakeOps) Resolve(_ context.Context, id string, approve bool, _ []string, _ int, _ float64) (bool, error) {
	verb := "deny"
	if approve {
		verb = "approve"
	}
	f.resolved = append(f.resolved, verb+":"+id)
	return f.resolveOK, nil
}
func (f *fakeOps) StreamConsents(context.Context) (<-chan gateway.ConsentEvent, func(), error) {
	return f.streamCh, func() { f.streamCancel = true }, nil
}

// drain runs a cmd tree synchronously, feeding resulting msgs back into the screen.
func drain(t *testing.T, s screen, cmd tea.Cmd) screen {
	t.Helper()
	if cmd == nil {
		return s
	}
	msg := cmd()
	if msg == nil {
		return s
	}
	switch m := msg.(type) {
	case tea.BatchMsg:
		for _, c := range m {
			s = drain(t, s, c)
		}
		return s
	}
	// tick/blink messages would loop forever; only feed our own msg types back
	switch msg.(type) {
	case targetsLoadedMsg, targetDetailMsg, policySavedMsg, entUpdatedMsg, introspectedMsg,
		keysLoadedMsg, keyMintedMsg, keyChannelsSavedMsg, eventsLoadedMsg, consentsLoadedMsg, resolvedMsg, flashMsg, errMsg:
		var next tea.Cmd
		s, next = s.update(msg)
		return drain(t, s, next)
	}
	return s
}

func keyMsg(k string) tea.KeyMsg {
	if k == " " {
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	}
	if len(k) == 1 {
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
	}
	switch k {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	}
	t := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
	return t
}

func press(t *testing.T, s screen, keys ...string) screen {
	t.Helper()
	for _, k := range keys {
		var cmd tea.Cmd
		s, cmd = s.update(keyMsg(k))
		s = drain(t, s, cmd)
	}
	return s
}

func TestTargetsScreen_ScopeToggle(t *testing.T) {
	f := &fakeOps{}
	var s screen = newTargetsScreen(f)
	s = drain(t, s, s.init())
	s = press(t, s, "enter") // open gh detail
	s = press(t, s, "right") // scopes pane
	s = press(t, s, " ")     // opt out files:read (first row)
	if len(f.disabledSet) != 1 || f.disabledSet[0][0] != "files:read" {
		t.Fatalf("SetDisabled calls = %v", f.disabledSet)
	}
	view := s.view(120, 40)
	if !strings.Contains(view, "opted out") {
		t.Fatalf("view must mark the opt-out:\n%s", view)
	}
}

func TestTargetsScreen_PolicyEditAndIntrospectMerge(t *testing.T) {
	f := &fakeOps{}
	var s screen = newTargetsScreen(f)
	s = drain(t, s, s.init())
	s = press(t, s, "enter") // detail
	s = press(t, s, "e")     // read → write on read_file
	ts := s.(*targetsScreen)
	if ts.tools[0].Effect != "write" || !ts.dirty {
		t.Fatalf("effect cycle failed: %+v dirty=%v", ts.tools[0], ts.dirty)
	}
	s = press(t, s, "I") // introspect merge adds new_tool
	ts = s.(*targetsScreen)
	if len(ts.tools) != 3 || !ts.newTools["new_tool"] {
		t.Fatalf("introspect merge failed: %+v", ts.tools)
	}
	view := s.view(120, 40)
	if !strings.Contains(view, "NEW") || !strings.Contains(view, "[unsaved]") {
		t.Fatalf("view must flag NEW rows and unsaved state:\n%s", view)
	}
}

func TestKeysScreen_MintAndRoll(t *testing.T) {
	f := &fakeOps{}
	var s screen = newKeysScreen(f)
	s = drain(t, s, s.init())

	// mint: n → type name → enter → plaintext box until dismissed
	s = press(t, s, "n", "c", "i", "enter")
	if len(f.mintedNames) != 1 || f.mintedNames[0] != "ci" {
		t.Fatalf("minted = %v", f.mintedNames)
	}
	ks := s.(*keysScreen)
	if ks.plaintext != "dgk_plaintext" || !ks.capturing() {
		t.Fatal("plaintext box must show and capture keys")
	}
	if !strings.Contains(s.view(100, 30), "dgk_plaintext") {
		t.Fatal("plaintext must render")
	}
	s = press(t, s, "j") // swallowed by the box
	if s.(*keysScreen).plaintext == "" {
		t.Fatal("random keys must not dismiss the plaintext box")
	}
	s = press(t, s, "enter") // dismiss
	// roll with confirm
	s = press(t, s, "R", "y")
	if len(f.rolledIDs) != 1 {
		t.Fatalf("rolled = %v", f.rolledIDs)
	}
	if s.(*keysScreen).plaintext != "dgk_rolled" {
		t.Fatal("roll must show the fresh plaintext once")
	}
}

func TestKeysScreen_ConsentPreset(t *testing.T) {
	f := &fakeOps{}
	var s screen = newKeysScreen(f)
	s = drain(t, s, s.init())
	s = press(t, s, "c") // open preset picker on akey_1
	if !s.(*keysScreen).picking {
		t.Fatal("picker must open")
	}
	s = press(t, s, "down", "down", "enter") // pick "in-chat first"
	if len(f.channelSets) != 1 || f.channelSets[0] != "akey_1=elicitation,console" {
		t.Fatalf("channelSets = %v", f.channelSets)
	}
}

func TestTargetsScreen_ScopeEffectCycle(t *testing.T) {
	f := &fakeOps{}
	var s screen = newTargetsScreen(f)
	s = drain(t, s, s.init())
	s = press(t, s, "enter", "right") // detail → entitlement pane
	s = press(t, s, "e")              // files:read (row 0): read → write on its tools
	ts := s.(*targetsScreen)
	if ts.tools[0].Effect != "write" || !ts.dirty {
		t.Fatalf("scope effect cycle failed: %+v dirty=%v", ts.tools[0], ts.dirty)
	}
	view := s.view(140, 40)
	if !strings.Contains(view, "write") || !strings.Contains(view, "[unsaved]") {
		t.Fatalf("entitlement pane must show the new effect + unsaved flag:\n%s", view)
	}
	// mcp:connect (last row) has no tools — cycling must refuse gracefully
	s = press(t, s, "down", "down", "e")
	if s.(*targetsScreen).tools[0].Effect != "write" {
		t.Fatal("cycling a tool-less scope must not touch other tools")
	}
}

func TestAlertsScreen_ApproveSubset(t *testing.T) {
	f := &fakeOps{resolveOK: true}
	f.consents = consentBundle{Live: []gateway.PendingView{{
		ID: "creq_1", TargetID: "gh", AgentName: "claude", Headline: "Send mail",
		Scopes: []gateway.ScopeView{{Scope: "files:read"}, {Scope: "mail:send"}},
	}}}
	var s screen = newAlertsScreen(f, true)
	s = drain(t, s, s.init())

	s = press(t, s, "a")         // open picker (all granted)
	s = press(t, s, "down", " ") // un-grant mail:send
	s = press(t, s, "enter")     // approve remainder
	if len(f.resolved) != 1 || f.resolved[0] != "approve:creq_1" {
		t.Fatalf("resolved = %v", f.resolved)
	}

	// deny path straight from the list
	f.consents = consentBundle{Live: []gateway.PendingView{{ID: "creq_2", TargetID: "gh", Scopes: []gateway.ScopeView{{Scope: "x:y"}}}}}
	s = drain(t, s, s.(*alertsScreen).load())
	s = press(t, s, "d")
	if f.resolved[len(f.resolved)-1] != "deny:creq_2" {
		t.Fatalf("resolved = %v", f.resolved)
	}
}

func TestAuditScreen_Filter(t *testing.T) {
	f := &fakeOps{}
	var s screen = newAuditScreen(f, false)
	s = drain(t, s, s.init())
	view := s.view(140, 30)
	if !strings.Contains(view, "read_file") {
		t.Fatalf("event row missing:\n%s", view)
	}
	s = press(t, s, "/", "z", "z", "enter")
	if got := s.view(140, 30); strings.Contains(got, "read_file") {
		t.Fatalf("filter zz must hide the row:\n%s", got)
	}
	s = press(t, s, "c")
	if got := s.view(140, 30); !strings.Contains(got, "read_file") {
		t.Fatal("clearing the filter must restore rows")
	}
}

func TestAlertsScreen_ActionBarVisible(t *testing.T) {
	f := &fakeOps{resolveOK: true}
	f.consents = consentBundle{Live: []gateway.PendingView{{ID: "creq_1", TargetID: "gh",
		Scopes: []gateway.ScopeView{{Scope: "files:read"}}}}}
	var s screen = newAlertsScreen(f, true)
	s = drain(t, s, s.init())
	view := s.view(140, 40)
	if !strings.Contains(view, "a approve") || !strings.Contains(view, "d deny") || !strings.Contains(view, "▸") {
		t.Fatalf("alerts panel must show its keys and the selection marker:\n%s", view)
	}
	s = press(t, s, "a")
	if got := s.view(140, 40); !strings.Contains(got, "space toggles a scope") {
		t.Fatalf("picker must show its keys:\n%s", got)
	}
}

func TestRoot_NewAskFlashesInstructions(t *testing.T) {
	f := &fakeOps{streamCh: make(chan gateway.ConsentEvent, 1)}
	r := newRootModel(f)
	r.stream = f.streamCh
	r.active = 0 // on Targets when the ask arrives
	m, cmd := r.Update(consentStreamMsg{ev: gateway.ConsentEvent{Type: "pending", ID: "creq_9"}})
	root := m.(*rootModel)
	_ = cmd
	// drain the batch for the flashMsg
	found := false
	var walk func(c tea.Cmd)
	walk = func(c tea.Cmd) {
		if c == nil || found {
			return
		}
		msg := c()
		if b, ok := msg.(tea.BatchMsg); ok {
			for _, cc := range b {
				walk(cc)
			}
			return
		}
		if fm, ok := msg.(flashMsg); ok && strings.Contains(fm.text, "Tab to Alerts") {
			found = true
		}
	}
	walk(cmd)
	if !found {
		t.Fatal("a new ask while on another tab must flash how to act on it")
	}
	_ = root
}

func TestRoot_StreamBumpsBadgeAndBell(t *testing.T) {
	f := &fakeOps{streamCh: make(chan gateway.ConsentEvent, 1)}
	r := newRootModel(f)
	r.stream = f.streamCh

	m, _ := r.Update(consentStreamMsg{ev: gateway.ConsentEvent{Type: "pending", ID: "creq_9"}})
	root := m.(*rootModel)
	if root.pendingAlerts != 1 {
		t.Fatalf("badge = %d, want 1", root.pendingAlerts)
	}
	m, _ = root.Update(consentStreamMsg{ev: gateway.ConsentEvent{Type: "resolved", ID: "creq_9"}})
	if m.(*rootModel).pendingAlerts != 0 {
		t.Fatalf("badge after resolve = %d, want 0", m.(*rootModel).pendingAlerts)
	}
}
