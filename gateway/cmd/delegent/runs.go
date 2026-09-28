package main

// Runs: the live picture of one task as it crosses agents. The activity log already records
// every call, consent ask, decision and response with the session it ran under and the
// parent session an agent echoed, so a "run" is simply the tree of sessions under one root
// (the harness's own grant). This file folds those rows into a sequence diagram —
// participants (you, the harness, each agent) as lifelines, the information passed between
// them as arrows — and a timeline with the full payloads. Nothing here is a new source of
// truth: it is a read model over store.Event.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"delegent.dev/gateway"
	"delegent.dev/gateway/store"
)

// runParticipant is one lifeline in the diagram.
type runParticipant struct {
	Name string
	Kind string // you | harness | agent
	X    int    // lifeline x in the SVG
}

// runRow is one arrow: something passed from one participant to another.
type runRow struct {
	Time    string
	Kind    string // call | ask | grant | deny | reply | error | stop | stop_agent | question | answer
	From    int    // participant index
	To      int
	Label   string // the short verb: a tool name, "approval?", "approved", "denied", "reply"
	Text    string // the payload excerpt on the arrow
	Full    string // the whole payload, for the timeline
	Tone    string // "" | ok | warn | bad
	Pending bool   // an ask no decision has landed on yet
	Target  string // the target an ask/decision is about (asks are drawn from the CALLER)
	At      int64  // unix ms
	Y       int
	// geometry for the template: the arrow runs X1→X2, the label sits at the midpoint
	X1, X2, Mid int
	Dashed      bool
}

// run is one conversation's work: every root session a client opened on one connection, and
// everything that happened under them. Root is the first of those sessions (the run's id).
type run struct {
	Root         string
	conn         string
	StartedAt    int64
	LastAt       int64
	Started      string
	Harness      string
	Title        string // first tool + message excerpt
	Status       string // running | waiting | done | refused
	StatusTone   string
	Participants []runParticipant
	Rows         []runRow
	Width        int
	Height       int
	HeaderH      int
	Sig          string // changes whenever a row is added or a pending ask resolves
	pendingCount int
	openCalls    int
	badRows      int
	refusals     int    // of badRows, the ones that were a "no" (a denial, a refused call), not errors
	stopped      bool   // a human stopped the run
	questions    int    // questions to the operator still waiting
	live         bool   // its root session still confers access (set by the page handler)
	Notice       string // shown once on the run page, after an action on it
	events       []*store.Event
}

// diagram geometry
const (
	runColW    = 200
	runLeft    = 24
	runHeaderH = 76
	runRowH    = 50
	runLabelN  = 30
	runTextN   = 64
)

// callerOf names the participant a row came FROM: an agent's key ("agent:<target>", as
// --mint-key and the dashboard issue them) maps to that agent's lifeline; a person's key is
// its own lifeline (the harness). Empty (a console decision carries no key) resolves to
// whoever last called the row's target.
func callerOf(e *store.Event, lastCaller map[string]string) string {
	if strings.HasPrefix(e.KeyName, "agent:") {
		return strings.TrimPrefix(e.KeyName, "agent:")
	}
	if e.KeyName != "" {
		return e.KeyName
	}
	return lastCaller[e.TargetID]
}

// buildRuns folds an ascending event stream into runs, newest first. Attribution: an event
// with a known session joins that session's run; an event echoing a known parent joins the
// parent's run (and its own session, once minted, joins too); an event with a brand-new root
// session starts a run and adopts the pre-session events of the same key on the same target
// (the ask that earned the grant). Events that fit nowhere — a refused root call that never
// earned a session, or a parent from a previous gateway process — are left out.
func buildRuns(events []*store.Event) []*run {
	// Events are stamped at the call site but appended asynchronously, so two rows of one call
	// can land in either order within a millisecond: settle ties by the order a call happens in.
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].CreatedAt != events[j].CreatedAt {
			return events[i].CreatedAt < events[j].CreatedAt
		}
		return typeRank(events[i].Type) < typeRank(events[j].Type)
	})
	owner := map[string]*run{}
	byConn := map[string]*run{} // one run per client connection (conversation)
	pending := map[string][]*store.Event{}
	var runs []*run
	orphanKey := func(e *store.Event) string { return e.KeyName + "|" + e.TargetID }
	for _, e := range events {
		switch e.Type {
		case store.EventConnection, store.EventDisconnected:
			continue
		}
		var r *run
		switch {
		case e.SessionHandle != "" && owner[e.SessionHandle] != nil:
			r = owner[e.SessionHandle]
		case e.ParentHandle != "" && owner[e.ParentHandle] != nil:
			r = owner[e.ParentHandle]
			if e.SessionHandle != "" {
				owner[e.SessionHandle] = r
			}
		case e.SessionHandle != "" && e.ParentHandle == "" && e.KeyName == "" && adoptDecision(runs, e) != nil:
			// A console decision recorded without its caller's identity (logs from before
			// decisions carried the key and parent): it belongs to the run whose ask on this
			// target is still open, not to a run of its own.
			r = adoptDecision(runs, e)
			owner[e.SessionHandle] = r
		case e.SessionHandle != "" && e.ParentHandle == "":
			// A root session. On a connection that already has a run — the same conversation
			// calling a second target directly — it joins that run; otherwise it starts one.
			if e.ConnID != "" && byConn[e.ConnID] != nil {
				r = byConn[e.ConnID]
			} else {
				r = &run{Root: e.SessionHandle, StartedAt: e.CreatedAt, Harness: e.KeyName, conn: e.ConnID}
				runs = append(runs, r)
				if e.ConnID != "" {
					byConn[e.ConnID] = r
				}
			}
			owner[e.SessionHandle] = r
			k := orphanKey(e)
			r.events = append(r.events, pending[k]...)
			delete(pending, k)
			if len(r.events) > 0 && r.events[0].CreatedAt < r.StartedAt {
				r.StartedAt = r.events[0].CreatedAt
			}
		case e.SessionHandle == "" && e.ParentHandle == "" && e.ConnID != "" && byConn[e.ConnID] != nil:
			// No session (for example a reply that arrived after the run was stopped and its
			// session revoked), on a connection that already has a run: it is that run's.
			r = byConn[e.ConnID]
		case e.SessionHandle == "" && e.ParentHandle == "":
			k := orphanKey(e)
			pending[k] = append(pending[k], e)
			continue
		default:
			continue
		}
		r.events = append(r.events, e)
		if e.CreatedAt > r.LastAt {
			r.LastAt = e.CreatedAt
		}
	}
	for _, r := range runs {
		// Adopted pre-session events were appended when their session appeared, which on a
		// multi-session run is after other events: restore time order before laying out.
		sort.SliceStable(r.events, func(i, j int) bool {
			if r.events[i].CreatedAt != r.events[j].CreatedAt {
				return r.events[i].CreatedAt < r.events[j].CreatedAt
			}
			return typeRank(r.events[i].Type) < typeRank(r.events[j].Type)
		})
		r.layout()
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].LastAt > runs[j].LastAt })
	return runs
}

// adoptDecision finds the newest run with an undecided ask on the event's target — the run a
// keyless permission decision answers. nil when there is none.
func adoptDecision(runs []*run, e *store.Event) *run {
	if e.Type != store.EventPermissionGranted && e.Type != store.EventPermissionDenied {
		return nil
	}
	for i := len(runs) - 1; i >= 0; i-- {
		asks, decided := 0, 0
		for _, x := range runs[i].events {
			if x.TargetID != e.TargetID {
				continue
			}
			switch x.Type {
			case store.EventPermissionRequested:
				asks++
			case store.EventPermissionGranted, store.EventPermissionDenied:
				decided++
			}
		}
		if asks > decided {
			return runs[i]
		}
	}
	return nil
}

// layout turns a run's events into participants and arrows.
func (r *run) layout() {
	index := map[string]int{}
	add := func(name, kind string) int {
		if i, ok := index[name]; ok {
			return i
		}
		index[name] = len(r.Participants)
		r.Participants = append(r.Participants, runParticipant{Name: name, Kind: kind})
		return index[name]
	}
	you := add("you", "you")
	if r.Harness != "" {
		add(r.Harness, "harness")
	}
	lastCaller := map[string]string{}
	open := map[string]int{}
	// A call that needs consent parks on its ask and returns to the caller without running (the
	// gateway answers it "pending" or "approved, retry"); what runs is the caller's next call,
	// which gets the reply. So the ask closes the call that raised it. awaiting remembers the
	// asked-for tool, only to label that next call "(retry)".
	awaiting := map[string]string{}
	questionRow := map[string]int{} // question id → its row, settled when the answer comes
	r.Started = evTime(r.StartedAt)
	for _, e := range r.events {
		caller := callerOf(e, lastCaller)
		if caller == "" {
			caller = r.Harness
		}
		target := e.TargetID
		row := runRow{Time: evTime(e.CreatedAt), At: e.CreatedAt}
		switch e.Type {
		case store.EventToolCall:
			lastCaller[target] = caller
			from := add(caller, kindOf(caller, r.Harness))
			to := add(target, "agent")
			row.Kind, row.From, row.To, row.Label = "call", from, to, e.Tool
			if awaiting[target] == e.Tool {
				row.Label += " (retry)"
			}
			open[target]++
			row.Full = callPayload(e)
			row.Text = excerpt(row.Full, runTextN)
			if r.Title == "" {
				r.Title = e.Tool
				if m := messageOf(e.Params); m != "" {
					r.Title += ": " + excerpt(m, 80)
				}
			}
		case store.EventPermissionRequested:
			if e.Tool != "" {
				awaiting[target] = e.Tool
				if open[target] > 0 {
					open[target]-- // the call that asked is parked: it never runs
				}
			}
			if lastCaller[target] == "" {
				lastCaller[target] = caller
			}
			from := add(caller, kindOf(caller, r.Harness))
			row.Kind, row.From, row.To, row.Label, row.Tone, row.Dashed, row.Target = "ask", from, you, "may it use "+target+"?", "warn", true, target
			row.Full = askPayload(e)
			row.Text = excerpt(row.Full, runTextN)
			row.Pending = true
		case store.EventPermissionGranted:
			to := add(caller, kindOf(caller, r.Harness))
			row.Kind, row.From, row.To, row.Label, row.Tone, row.Dashed, row.Target = "grant", you, to, "approved for "+target, "ok", true, target
			row.Full = strings.Join(e.Scopes, ", ")
			row.Text = excerpt(row.Full, runTextN)
			r.settle(target)
		case store.EventPermissionDenied:
			to := add(caller, kindOf(caller, r.Harness))
			row.Kind, row.From, row.To, row.Label, row.Tone, row.Dashed, row.Target = "deny", you, to, "denied for "+target, "bad", true, target
			row.Full = e.Reason
			row.Text = excerpt(row.Full, runTextN)
			r.settle(target)
			// A refusal with no ask before it (the relationship map's backstop, an unclassified
			// tool) ends the call that caused it; after an ask, the ask already did.
			if awaiting[target] == "" && open[target] > 0 {
				open[target]--
			}
			delete(awaiting, target)
			r.badRows++
			r.refusals++
		case store.EventToolResponse:
			from := add(target, "agent")
			to := add(caller, kindOf(caller, r.Harness))
			row.Kind, row.From, row.To, row.Label, row.Tone = "reply", from, to, "reply", "ok"
			if e.Error != "" {
				row.Tone, row.Label = "bad", "error reply"
				r.badRows++
			}
			row.Full = resultPayload(e)
			row.Text = excerpt(row.Full, runTextN)
			if open[target] > 0 {
				open[target]--
			}
			delete(awaiting, target)
		case store.EventQuestionAsked:
			var p struct {
				ID       string   `json:"question_id"`
				Question string   `json:"question"`
				Choices  []string `json:"choices"`
			}
			json.Unmarshal(e.Params, &p)
			from := add(caller, kindOf(caller, r.Harness))
			row.Kind, row.From, row.To, row.Label, row.Tone = "question", from, you, "asks you", "warn"
			row.Full = p.Question
			if len(p.Choices) > 0 {
				row.Full += "\n\nChoices: " + strings.Join(p.Choices, " · ")
			}
			row.Text = excerpt(p.Question, runTextN)
			row.Pending = true
			questionRow[p.ID] = len(r.Rows)
		case store.EventQuestionAnswered:
			var res struct {
				ID     string `json:"question_id"`
				Status string `json:"status"`
				Answer string `json:"answer"`
			}
			json.Unmarshal(e.Result, &res)
			to := add(caller, kindOf(caller, r.Harness))
			row.Kind, row.From, row.To, row.Tone = "answer", you, to, "ok"
			switch res.Status {
			case "answered":
				row.Label, row.Full = "answered", res.Answer
			default:
				row.Label, row.Tone, row.Full = res.Status, "bad", e.Reason
			}
			row.Text = excerpt(row.Full, runTextN)
			if i, ok := questionRow[res.ID]; ok {
				r.Rows[i].Pending = false
			}
		case store.EventRunStopped:
			// You stopped the run: the arrow goes to whoever you started it through.
			to := you
			if r.Harness != "" {
				to = add(r.Harness, "harness")
			} else if len(r.Participants) > 1 {
				to = 1
			}
			row.Kind, row.From, row.To, row.Label, row.Tone = "stop", you, to, "stopped the run", "bad"
			row.Full = e.Reason
			row.Text = excerpt(row.Full, runTextN)
			r.stopped = true
		case store.EventAgentStopped:
			// You stopped one agent: its calls end (whoever waited on it gets its task back
			// cancelled); the rest of the run carries on.
			to := add(target, "agent")
			row.Kind, row.From, row.To, row.Label, row.Tone, row.Target = "stop_agent", you, to, "stopped "+target, "bad", target
			row.Full = e.Reason
			row.Text = excerpt(row.Full, runTextN)
			open[target] = 0
		case store.EventError:
			from := add(target, "agent")
			to := add(caller, kindOf(caller, r.Harness))
			row.Kind, row.From, row.To, row.Label, row.Tone = "error", from, to, "error", "bad"
			row.Full = e.Error
			if row.Full == "" {
				row.Full = e.Reason
			}
			row.Text = excerpt(row.Full, runTextN)
			if open[target] > 0 {
				open[target]--
			}
			r.badRows++
			if e.Error == "" { // the gateway refused the call (an unclassified tool, …), not an upstream failure
				r.refusals++
			}
		default:
			continue
		}
		if row.Label == "" {
			row.Label = e.Type
		}
		r.Rows = append(r.Rows, row)
	}
	for _, n := range open {
		r.openCalls += n
	}
	for i := range r.Rows {
		if r.Rows[i].Pending {
			r.pendingCount++
			if r.Rows[i].Kind == "question" {
				r.questions++
			}
		}
	}
	if r.stopped {
		// Nothing in a stopped run is still waiting on you or working.
		for i := range r.Rows {
			r.Rows[i].Pending = false
		}
		r.pendingCount = 0
	}
	switch {
	case r.stopped:
		r.Status, r.StatusTone = "stopped", "bad"
	case r.pendingCount > 0 && r.pendingCount == r.questions:
		r.Status, r.StatusTone = "waiting for your answer", "warn"
	case r.pendingCount > 0:
		r.Status, r.StatusTone = "waiting for your approval", "warn"
	case r.openCalls > 0:
		r.Status, r.StatusTone = "running", ""
	case r.refusals > 0:
		r.Status, r.StatusTone = "finished with refusals", "bad"
	case r.badRows > 0:
		r.Status, r.StatusTone = "finished with errors", "bad"
	default:
		r.Status, r.StatusTone = "done", "ok"
	}
	// geometry
	for i := range r.Participants {
		r.Participants[i].X = runLeft + i*runColW + runColW/2
	}
	r.HeaderH = runHeaderH
	for i := range r.Rows {
		row := &r.Rows[i]
		row.Y = runHeaderH + (i+1)*runRowH
		row.X1 = r.Participants[row.From].X
		row.X2 = r.Participants[row.To].X
		row.Mid = (row.X1 + row.X2) / 2
	}
	r.Width = runLeft*2 + len(r.Participants)*runColW
	r.Height = runHeaderH + (len(r.Rows)+1)*runRowH
	r.Sig = fmt.Sprintf("%d:%d:%d", len(r.Rows), r.pendingCount, r.LastAt)
}

// settle marks the latest still-pending ask about a target as decided.
func (r *run) settle(target string) {
	for i := len(r.Rows) - 1; i >= 0; i-- {
		if r.Rows[i].Kind == "ask" && r.Rows[i].Target == target && r.Rows[i].Pending {
			r.Rows[i].Pending = false
			return
		}
	}
}

func kindOf(name, harness string) string {
	if name == harness {
		return "harness"
	}
	return "agent"
}

// messageOf pulls the free-text message out of a call's params (an agent skill's input).
func messageOf(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	s, _ := m["message"].(string)
	return s
}

// callPayload renders what a call carried: the message when there is one, else the params.
func callPayload(e *store.Event) string {
	if m := messageOf(e.Params); m != "" {
		return m
	}
	if len(e.Params) > 0 {
		var m map[string]any
		if json.Unmarshal(e.Params, &m) == nil {
			delete(m, "_delegent_intent")
			if len(m) == 0 {
				return ""
			}
			b, _ := json.Marshal(m)
			return string(b)
		}
		return string(e.Params)
	}
	return ""
}

func askPayload(e *store.Event) string {
	s := strings.Join(e.Scopes, ", ")
	if e.Intent != "" {
		s += " — why: " + e.Intent
	}
	return s
}

// resultPayload flattens a tool result: the text content when present, else the raw JSON.
func resultPayload(e *store.Event) string {
	if e.Error != "" {
		return e.Error
	}
	if len(e.Result) == 0 {
		return ""
	}
	var res struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Structured map[string]any `json:"structuredContent"`
		Truncated  int            `json:"_truncated"`
	}
	if json.Unmarshal(e.Result, &res) == nil {
		var parts []string
		for _, c := range res.Content {
			if c.Text != "" {
				parts = append(parts, c.Text)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "\n")
		}
		if t, ok := res.Structured["text"].(string); ok && t != "" {
			return t
		}
		if res.Truncated > 0 {
			return fmt.Sprintf("(result of %d bytes, not captured)", res.Truncated)
		}
	}
	return string(e.Result)
}

// excerpt is one line of at most n runes.
func excerpt(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// --- handlers ---

func (w *webApp) loadRuns(r *http.Request) []*run {
	rows, err := w.e.st.ListEvents(r.Context(), store.EventFilter{UserID: w.e.operator, Limit: store.EventLimitAll})
	if err != nil {
		return nil
	}
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 { // newest-first → ascending
		rows[i], rows[j] = rows[j], rows[i]
	}
	if keys, err := w.e.st.ListAgentKeys(r.Context(), w.e.operator); err == nil {
		attributeAgentKeys(rows, keys)
	}
	return buildRuns(rows)
}

// attributeAgentKeys puts every call made with a key issued to an agent on that agent's
// lifeline, whatever the key is called. A key minted on the command line is named
// "agent:<id>", which callerOf reads directly; a key minted in the dashboard carries its own
// name ("pm prod") and only its AgentTargetID says whose it is. Such rows are relabelled
// "agent:<id>" here, so one agent never shows up as two participants. A key is matched on
// prefix and name together. A console decision records the key's name but no prefix; it is
// matched on the name alone, and only when that name belongs to exactly one key, an agent's.
func attributeAgentKeys(events []*store.Event, keys []*store.AgentKey) {
	agentOf := map[string]string{}
	byName := map[string]string{} // name → agent, "" when the name is shared or a person's
	for _, k := range keys {
		if k.AgentTargetID != "" {
			agentOf[k.Prefix+"|"+k.Name] = k.AgentTargetID
		}
		if _, seen := byName[k.Name]; seen {
			byName[k.Name] = ""
		} else {
			byName[k.Name] = k.AgentTargetID
		}
	}
	for _, e := range events {
		if strings.HasPrefix(e.KeyName, "agent:") {
			continue
		}
		id := agentOf[e.KeyPrefix+"|"+e.KeyName]
		if id == "" && e.KeyPrefix == "" {
			id = byName[e.KeyName]
		}
		if id != "" {
			e.KeyName = "agent:" + id
		}
	}
}

func typeRank(t string) int {
	switch t {
	case store.EventToolCall:
		return 0
	case store.EventPermissionRequested:
		return 1
	case store.EventPermissionGranted, store.EventPermissionDenied:
		return 2
	case store.EventToolResponse, store.EventError:
		return 3
	}
	return 4
}

func (w *webApp) findRun(r *http.Request, root string) *run {
	for _, x := range w.loadRuns(r) {
		if x.Root == root {
			return x
		}
	}
	return nil
}

// findRunByConn finds the run of one client connection — how a playground run is located
// from the connection id its events carry.
func (w *webApp) findRunByConn(r *http.Request, conn string) *run {
	for _, x := range w.loadRuns(r) {
		if x.conn == conn {
			return x
		}
	}
	return nil
}

func (w *webApp) runsPage(rw http.ResponseWriter, r *http.Request) {
	runs := w.loadRuns(r)
	running, waiting := 0, 0
	for _, run := range runs {
		if run.StatusTone == "warn" {
			waiting++
		} else if run.Status == "running" {
			running++
		}
	}
	w.page(rw, r, "", "runsPage", map[string]any{"Runs": runs, "Running": running, "Waiting": waiting})
}

// Stoppable reports whether stopping the run would still do something: it is going (a call
// or an ask is open), or it still holds access — an agent task can outlive the call that
// started it, and a finished run's sessions stay live until they expire.
func (r *run) Stoppable() bool {
	return !r.stopped && (r.pendingCount > 0 || r.openCalls > 0 || r.live)
}

// markLive records whether the run's root session still confers access.
func (w *webApp) markLive(r *http.Request, x *run) {
	ss, err := w.e.st.GetSession(r.Context(), x.Root)
	x.live = err == nil && ss.RevokedAt == 0 && (ss.ExpiresAt == 0 || ss.ExpiresAt > time.Now().UnixMilli())
}

// stopRun stops a whole run: every session in it is revoked, its waiting asks are denied, and
// the agent tasks it started are cancelled on the agents (see Registry.StopRun).
func (w *webApp) stopRun(rw http.ResponseWriter, r *http.Request) {
	root := r.PathValue("id")
	var known []gateway.RunTask
	if x := w.findRun(r, root); x != nil {
		known = unfinishedTasks(x)
	}
	rep, err := w.reg.StopRun(w.e.operator, root, known...)
	if errors.Is(err, gateway.ErrNoSuchRun) {
		w.page(rw, r, "", "runMissing", map[string]any{"Root": root})
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	x := w.findRun(r, root)
	if x == nil {
		w.page(rw, r, "", "runMissing", map[string]any{"Root": root})
		return
	}
	x.Notice = stopNotice(rep)
	w.markLive(r, x)
	w.page(rw, r, "", "runPage", x)
}

// unfinishedTasks lists the agent tasks a run's log last saw still going: each agent reply
// carries its task's id and state (structuredContent), and a later reply for the same task
// supersedes an earlier one.
func unfinishedTasks(x *run) []gateway.RunTask {
	type seen struct {
		task  gateway.RunTask
		state string
	}
	last := map[string]seen{}
	var order []string
	for _, e := range x.events {
		if e.Type != store.EventToolResponse || len(e.Result) == 0 || e.SessionHandle == "" {
			continue
		}
		var res struct {
			Structured struct {
				TaskID string `json:"task_id"`
				State  string `json:"state"`
			} `json:"structuredContent"`
		}
		if json.Unmarshal(e.Result, &res) != nil || res.Structured.TaskID == "" {
			continue
		}
		k := e.TargetID + "|" + res.Structured.TaskID
		if _, ok := last[k]; !ok {
			order = append(order, k)
		}
		last[k] = seen{gateway.RunTask{Target: e.TargetID, TaskID: res.Structured.TaskID, Session: e.SessionHandle}, res.Structured.State}
	}
	var out []gateway.RunTask
	for _, k := range order {
		switch last[k].state {
		case "completed", "failed", "canceled", "rejected":
			continue
		}
		out = append(out, last[k].task)
	}
	return out
}

// agentTask is one task a run gave an agent, as its log tells it.
type agentTask struct {
	TaskID  string `json:"task_id"`
	State   string `json:"state"`
	Asked   string `json:"asked"`    // the message that started it
	AskedBy string `json:"asked_by"` // who sent it
	At      int64  `json:"at"`
	Latest  string `json:"latest"` // the agent's last word on it (its reply, or its status note)
	Live    bool   `json:"live"`   // Latest and State were read from the agent just now
	session string
}

// agentTasks lists the tasks a run gave one agent, oldest first: each agent reply carries its
// task's id and state, and the call it answers carries what the agent was asked. A later
// reply on the same task (a teammate checking on it) updates its state.
func agentTasks(x *run, name string) []*agentTask {
	byID := map[string]*agentTask{}
	var out []*agentTask
	var lastAsked, lastBy string
	lastCaller := map[string]string{}
	for _, e := range x.events {
		if e.TargetID != name {
			continue
		}
		switch e.Type {
		case store.EventToolCall:
			lastBy = callerOf(e, lastCaller)
			lastCaller[e.TargetID] = lastBy
			lastAsked = callPayload(e)
		case store.EventToolResponse:
			var res struct {
				Structured struct {
					TaskID string `json:"task_id"`
					State  string `json:"state"`
				} `json:"structuredContent"`
			}
			if len(e.Result) == 0 || json.Unmarshal(e.Result, &res) != nil || res.Structured.TaskID == "" {
				continue
			}
			t := byID[res.Structured.TaskID]
			if t == nil {
				t = &agentTask{TaskID: res.Structured.TaskID, Asked: lastAsked, AskedBy: lastBy, At: e.CreatedAt}
				if t.AskedBy == "" {
					t.AskedBy = x.Harness
				}
				byID[t.TaskID] = t
				out = append(out, t)
			}
			t.State, t.Latest = res.Structured.State, resultPayload(e)
			if e.SessionHandle != "" {
				t.session = e.SessionHandle
			}
		}
	}
	return out
}

func taskFinished(state string) bool {
	switch state {
	case "completed", "failed", "canceled", "rejected":
		return true
	}
	return false
}

// runSessions is every session a run's events were made under.
func runSessions(x *run) map[string]bool {
	out := map[string]bool{x.Root: true}
	for _, e := range x.events {
		if e.SessionHandle != "" {
			out[e.SessionHandle] = true
		}
		if e.ParentHandle != "" {
			out[e.ParentHandle] = true
		}
	}
	return out
}

// inspectAgent gathers one agent's tasks in a run: those the log tells of, plus those the
// gateway is still waiting on (a first call's task has no reply in the log yet), with the
// unfinished ones' state read from the agent. isAgent is false for a target that is not an
// A2A agent: it has no tasks to read or stop.
func (w *webApp) inspectAgent(r *http.Request, x *run, name string) (tasks []*agentTask, isAgent bool) {
	tasks = agentTasks(x, name)
	t, err := w.e.st.GetTarget(r.Context(), name)
	if err != nil || t.Kind != gateway.TargetKindA2A {
		return tasks, false
	}
	known := map[string]*agentTask{}
	for _, t := range tasks {
		known[t.TaskID] = t
	}
	for _, rt := range w.reg.RunningAgentTasks(r.Context(), name, runSessions(x)) {
		if t := known[rt.TaskID]; t != nil {
			if t.session == "" {
				t.session = rt.Session
			}
			continue
		}
		t := &agentTask{TaskID: rt.TaskID, State: "working", Asked: rt.Message, At: rt.StartedAt, session: rt.Session}
		t.AskedBy = lastCallerOf(x, name, rt.Message)
		known[t.TaskID] = t
		tasks = append(tasks, t)
	}
	for _, t := range tasks {
		if taskFinished(t.State) {
			continue
		}
		if state, text, err := w.reg.AgentTaskStatus(r.Context(), gateway.RunTask{Target: name, TaskID: t.TaskID, Session: t.session}); err == nil && state != "" {
			t.State, t.Live = state, true
			if text != "" {
				t.Latest = text
			}
		}
	}
	return tasks, true
}

// lastCallerOf names who last sent an agent this message in the run (the harness if unknown).
func lastCallerOf(x *run, target, msg string) string {
	who := ""
	lastCaller := map[string]string{}
	for _, e := range x.events {
		if e.Type != store.EventToolCall || e.TargetID != target {
			continue
		}
		c := callerOf(e, lastCaller)
		lastCaller[target] = c
		if messageOf(e.Params) == msg {
			who = c
		}
	}
	if who == "" {
		who = x.Harness
	}
	return who
}

// agentInspect is the JSON behind the run page's agent panel: what one agent was asked in
// the run, and where each of those tasks stands now.
func (w *webApp) agentInspect(rw http.ResponseWriter, r *http.Request) {
	x := w.findRun(r, r.PathValue("id"))
	name := r.PathValue("name")
	if x == nil {
		http.NotFound(rw, r)
		return
	}
	tasks, isAgent := w.inspectAgent(r, x, name)
	stoppable := false
	for _, t := range tasks {
		t.Latest = excerpt(t.Latest, 600)
		if isAgent && !taskFinished(t.State) {
			stoppable = true
		}
	}
	if tasks == nil {
		tasks = []*agentTask{}
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(rw).Encode(map[string]any{
		"name": name, "agent": isAgent, "tasks": tasks, "stoppable": stoppable && !x.stopped,
	})
}

// stopAgent cancels one agent's unfinished tasks in a run, leaving the rest of the run going.
func (w *webApp) stopAgent(rw http.ResponseWriter, r *http.Request) {
	// Only the run page's script posts here, and it marks the request: a cross-site form cannot.
	if r.Header.Get("HX-Request") != "true" {
		http.Error(rw, "forbidden", http.StatusForbidden)
		return
	}
	x := w.findRun(r, r.PathValue("id"))
	name := r.PathValue("name")
	if x == nil {
		http.NotFound(rw, r)
		return
	}
	tasks, _ := w.inspectAgent(r, x, name)
	var cancel []gateway.RunTask
	for _, t := range tasks {
		if !taskFinished(t.State) {
			cancel = append(cancel, gateway.RunTask{Target: name, TaskID: t.TaskID, Session: t.session})
		}
	}
	n := w.reg.StopAgent(w.e.operator, x.Root, name, cancel)
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(map[string]any{"canceled": n})
}

func stopNotice(rep gateway.StopReport) string {
	n := "Run stopped. "
	if rep.Sessions == 0 {
		n += "Its sessions had already ended with a gateway restart"
	} else {
		n += plural(rep.Revoked, "session") + " revoked"
	}
	if rep.Canceled > 0 {
		n += ", " + plural(rep.Canceled, "agent task") + " cancelled"
	}
	if rep.Denied > 0 {
		n += ", " + plural(rep.Denied, "waiting approval") + " denied"
	}
	if rep.Questions > 0 {
		n += ", " + plural(rep.Questions, "waiting question") + " cancelled"
	}
	return n + ". Any agent still working can make no further calls."
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func (w *webApp) runPage(rw http.ResponseWriter, r *http.Request) {
	x := w.findRun(r, r.PathValue("id"))
	if x == nil {
		w.page(rw, r, "", "runMissing", map[string]any{"Root": r.PathValue("id")})
		return
	}
	w.markLive(r, x)
	w.page(rw, r, "", "runPage", x)
}

// runState is the JSON the live flow view polls: participants, rows, status, and a signature
// (204 when the caller already has this signature).
func (w *webApp) runState(rw http.ResponseWriter, r *http.Request) {
	x := w.findRun(r, r.PathValue("id"))
	if x == nil {
		http.NotFound(rw, r)
		return
	}
	if x.Sig == r.URL.Query().Get("known") {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	type jsonRow struct {
		Kind    string `json:"kind"`
		From    int    `json:"from"`
		To      int    `json:"to"`
		Label   string `json:"label"`
		Text    string `json:"text"`
		Full    string `json:"full"`
		Tone    string `json:"tone"`
		Pending bool   `json:"pending"`
		Target  string `json:"target,omitempty"`
		Time    string `json:"time"`
		At      int64  `json:"at"`
	}
	type jsonParticipant struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	}
	out := struct {
		Root         string            `json:"root"`
		Title        string            `json:"title"`
		Status       string            `json:"status"`
		StatusTone   string            `json:"status_tone"`
		Sig          string            `json:"sig"`
		Participants []jsonParticipant `json:"participants"`
		Rows         []jsonRow         `json:"rows"`
	}{Root: x.Root, Title: x.Title, Status: x.Status, StatusTone: x.StatusTone, Sig: x.Sig}
	for _, p := range x.Participants {
		out.Participants = append(out.Participants, jsonParticipant{Name: p.Name, Kind: p.Kind})
	}
	for _, row := range x.Rows {
		out.Rows = append(out.Rows, jsonRow{Kind: row.Kind, From: row.From, To: row.To, Label: row.Label, Text: row.Text, Full: row.Full, Tone: row.Tone, Pending: row.Pending, Target: row.Target, Time: row.Time, At: row.At})
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(rw).Encode(out)
}

// runDiagram is the polled partial: 204 when nothing changed since the caller's signature.
func (w *webApp) runDiagram(rw http.ResponseWriter, r *http.Request) {
	x := w.findRun(r, r.PathValue("id"))
	if x == nil {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	if x.Sig == r.URL.Query().Get("known") {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	w.render(rw, "runDiagram", x)
}
