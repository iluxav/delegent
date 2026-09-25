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
	"fmt"
	"net/http"
	"sort"
	"strings"

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
	Kind    string // call | ask | grant | deny | reply | error
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
	// awaiting marks a target whose last call parked on consent: the client's next call of
	// the same tool is that call retried (the console path never answers the first one), not
	// a second open call.
	awaiting := map[string]string{}
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
			// Every further call of the tool while its ask is open is the same call retried
			// (the client re-sends until the grant lands); the reply or refusal closes it.
			if awaiting[target] == e.Tool {
				row.Label += " (retry)"
			} else {
				open[target]++
			}
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
			if open[target] > 0 {
				open[target]--
			}
			delete(awaiting, target)
			r.badRows++
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
		}
	}
	switch {
	case r.pendingCount > 0:
		r.Status, r.StatusTone = "waiting for your approval", "warn"
	case r.openCalls > 0:
		r.Status, r.StatusTone = "running", ""
	case r.badRows > 0:
		r.Status, r.StatusTone = "finished with refusals", "bad"
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
	return buildRuns(rows)
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

func (w *webApp) runsPage(rw http.ResponseWriter, r *http.Request) {
	w.page(rw, r, "", "runsPage", map[string]any{"Runs": w.loadRuns(r)})
}

func (w *webApp) runPage(rw http.ResponseWriter, r *http.Request) {
	x := w.findRun(r, r.PathValue("id"))
	if x == nil {
		w.page(rw, r, "", "runMissing", map[string]any{"Root": r.PathValue("id")})
		return
	}
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
