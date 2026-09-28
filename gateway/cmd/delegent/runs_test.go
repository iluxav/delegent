package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"delegent.dev/gateway/a2a"
	"delegent.dev/gateway/store"
)

// ev builds one activity-log row for the run tests.
func ev(t, key, target, tool, sess, parent string, at int64, extra func(*store.Event)) *store.Event {
	e := &store.Event{Type: t, KeyName: key, TargetID: target, Tool: tool, SessionHandle: sess, ParentHandle: parent, CreatedAt: at, UserID: "u"}
	if extra != nil {
		extra(e)
	}
	return e
}

func params(msg string) func(*store.Event) {
	return func(e *store.Event) {
		e.Params, _ = json.Marshal(map[string]any{"message": msg, "_delegent_intent": "why"})
	}
}

func result(text string) func(*store.Event) {
	return func(e *store.Event) {
		e.Result, _ = json.Marshal(map[string]any{"content": []map[string]any{{"type": "text", "text": text}}})
	}
}

// A harness call earns a root session (its pre-session ask is adopted), an agent then calls
// two targets under it, one ask is still pending: one run, four lifelines, a live status.
func TestBuildRunsGroupsHops(t *testing.T) {
	events := []*store.Event{
		ev(store.EventConnection, "laptop", "researcher", "", "", "", 1, nil),
		ev(store.EventToolCall, "laptop", "researcher", "research_topic", "", "", 2, params("research solar")),
		ev(store.EventPermissionRequested, "laptop", "researcher", "research_topic", "", "", 3, func(e *store.Event) { e.Scopes = []string{"data:read"} }),
		ev(store.EventPermissionGranted, "laptop", "researcher", "research_topic", "sess_root", "", 4, nil),
		ev(store.EventToolCall, "laptop", "researcher", "research_topic", "sess_root", "", 5, params("research solar")),
		ev(store.EventToolCall, "agent:researcher", "librarian", "search_docs", "", "sess_root", 6, params("solar")),
		ev(store.EventPermissionRequested, "agent:researcher", "librarian", "search_docs", "", "sess_root", 7, nil),
		ev(store.EventPermissionGranted, "", "librarian", "", "sess_child", "", 8, nil), // a console decision: no key, no parent
		ev(store.EventToolCall, "agent:researcher", "librarian", "search_docs", "sess_child", "sess_root", 9, params("solar")),
		ev(store.EventToolResponse, "agent:researcher", "librarian", "search_docs", "sess_child", "sess_root", 10, result("2 notes")),
		ev(store.EventToolCall, "agent:researcher", "mailer", "send_email", "", "sess_root", 11, params("To: bob")),
		ev(store.EventPermissionRequested, "agent:researcher", "mailer", "send_email", "", "sess_root", 12, func(e *store.Event) { e.Scopes = []string{"mail:send"}; e.Intent = "asked to" }),
		// an unrelated, still-orphan root ask from another key
		ev(store.EventToolCall, "other", "notion", "search", "", "", 13, nil),
	}
	runs := buildRuns(events)
	if len(runs) != 1 {
		t.Fatalf("got %d runs, want 1 (the orphan must not become one)", len(runs))
	}
	r := runs[0]
	if r.Root != "sess_root" || r.Harness != "laptop" || r.StartedAt != 2 {
		t.Errorf("run = root %s harness %s started %d", r.Root, r.Harness, r.StartedAt)
	}
	var names []string
	for _, p := range r.Participants {
		names = append(names, p.Name+"/"+p.Kind)
	}
	if got := strings.Join(names, " "); got != "you/you laptop/harness researcher/agent librarian/agent mailer/agent" {
		t.Errorf("participants = %s", got)
	}
	if r.Status != "waiting for your approval" || r.pendingCount != 1 {
		t.Errorf("status = %q pending=%d", r.Status, r.pendingCount)
	}
	// the librarian call parked on consent and was retried after the grant: one open call,
	// closed by the one reply — never two
	if r.openCalls != 2 { // research_topic (still running) + send_email (waiting)
		t.Errorf("open calls = %d, want 2", r.openCalls)
	}
	retries := 0
	for _, row := range r.Rows {
		if row.Kind == "call" && strings.HasSuffix(row.Label, "(retry)") {
			retries++
		}
	}
	if retries != 2 { // research_topic and search_docs were each retried after their grant
		t.Errorf("retries = %d, want 2", retries)
	}
	if !strings.HasPrefix(r.Title, "research_topic: research solar") {
		t.Errorf("title = %q", r.Title)
	}
	// the console grant with no key is drawn from you to the researcher (the party that asked
	// to use the librarian); the librarian's reply goes back to the researcher too
	var grant, reply *runRow
	for i := range r.Rows {
		switch r.Rows[i].Kind {
		case "grant":
			if r.Rows[i].Target == "librarian" {
				grant = &r.Rows[i]
			}
		case "reply":
			reply = &r.Rows[i]
		}
	}
	if grant == nil || r.Participants[grant.From].Name != "you" || r.Participants[grant.To].Name != "researcher" {
		t.Errorf("librarian grant row = %+v", grant)
	}
	if reply == nil || r.Participants[reply.To].Name != "researcher" || reply.Text != "2 notes" {
		t.Errorf("reply row = %+v", reply)
	}
	// the first librarian ask was settled by the grant; the mailer ask is the pending one
	for _, row := range r.Rows {
		if row.Kind == "ask" && row.Target == "librarian" && row.Pending {
			t.Error("librarian ask still pending after its grant")
		}
		if row.Kind == "ask" && row.Target == "mailer" && (!row.Pending || r.Participants[row.From].Name != "researcher") {
			t.Errorf("mailer ask row = %+v", row)
		}
	}
	if r.Width <= 0 || r.Height <= r.HeaderH {
		t.Errorf("geometry %dx%d", r.Width, r.Height)
	}
}

func TestBuildRunsStatuses(t *testing.T) {
	done := buildRuns([]*store.Event{
		ev(store.EventPermissionGranted, "k", "t", "", "s1", "", 1, nil),
		ev(store.EventToolCall, "k", "t", "x", "s1", "", 2, nil),
		ev(store.EventToolResponse, "k", "t", "x", "s1", "", 3, result("ok")),
	})
	if done[0].Status != "done" {
		t.Errorf("done run status = %q", done[0].Status)
	}
	running := buildRuns([]*store.Event{
		ev(store.EventPermissionGranted, "k", "t", "", "s1", "", 1, nil),
		ev(store.EventToolCall, "k", "t", "x", "s1", "", 2, nil),
	})
	if running[0].Status != "running" {
		t.Errorf("running run status = %q", running[0].Status)
	}
	refused := buildRuns([]*store.Event{
		ev(store.EventPermissionGranted, "k", "t", "", "s1", "", 1, nil),
		ev(store.EventToolCall, "agent:t", "u", "y", "", "s1", 2, nil),
		ev(store.EventPermissionDenied, "agent:t", "u", "y", "", "s1", 3, func(e *store.Event) { e.Reason = "depth exhausted" }),
	})
	if refused[0].Status != "finished with refusals" || refused[0].openCalls != 0 {
		t.Errorf("refused run status = %q open=%d", refused[0].Status, refused[0].openCalls)
	}
}

// TestRunsPreview renders the newest run of a real activity log to an SVG file, for eyeballing
// the diagram. Skipped unless DELEGENT_EVENTS_FILE and DELEGENT_RUNS_SVG are set.
func TestRunsPreview(t *testing.T) {
	in, out := os.Getenv("DELEGENT_EVENTS_FILE"), os.Getenv("DELEGENT_RUNS_SVG")
	if in == "" || out == "" {
		t.Skip("set DELEGENT_EVENTS_FILE and DELEGENT_RUNS_SVG to render a preview")
	}
	f, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var events []*store.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var e store.Event
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			events = append(events, &e)
		}
	}
	runs := buildRuns(events)
	if len(runs) == 0 {
		t.Fatal("no runs in the log")
	}
	tpl := template.Must(template.New("").Funcs(template.FuncMap{"join": strings.Join, "lower": strings.ToLower, "time": evTime}).ParseFS(webTemplates, "web/templates/*.html"))
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "runDiagram", runs[0]); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	svg := html[strings.Index(html, "<svg") : strings.Index(html, "</svg>")+6]
	css, _ := os.ReadFile("web/static/input.css")
	root := ":root{--color-paper:#11171c;--color-panel:#192128;--color-ink:#e6edf2;--color-ink-soft:#a4b2bd;--color-ink-faint:#8294a2;--color-line:#2b3842;--color-accent-line:#4c5968;--color-ok:#b9c7d5;--color-warn:#dfbd84;--color-bad:#e9a0a4;--color-yellow:#dfcd96;--color-purple:#beb1df}"
	styled := strings.Replace(svg, "<defs>", "<style>"+root+"svg{background:#192128}"+string(css[strings.Index(string(css), "/* --- runs"):])+"</style><defs>", 1)
	// rasterizers such as rsvg do not resolve CSS variables: inline the palette for the file
	for _, kv := range [][2]string{{"paper", "#11171c"}, {"panel", "#192128"}, {"ink-soft", "#a4b2bd"}, {"ink-faint", "#8294a2"}, {"ink", "#e6edf2"}, {"line", "#2b3842"}, {"accent-line", "#4c5968"}, {"ok", "#b9c7d5"}, {"warn", "#dfbd84"}, {"bad", "#e9a0a4"}, {"yellow", "#dfcd96"}, {"purple", "#beb1df"}} {
		styled = strings.ReplaceAll(styled, "var(--color-"+kv[0]+")", kv[1])
	}
	if err := os.WriteFile(out, []byte(styled), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("run %s: %d participants, %d rows, status %s", runs[0].Root, len(runs[0].Participants), len(runs[0].Rows), runs[0].Status)
}

// The runs pages serve through the dashboard: the list, one run (as a full page and as an
// htmx pane), and the polled diagram that answers 204 while nothing changed.
func TestRunsPages(t *testing.T) {
	ts, e, logs := newDashboard(t)
	c := browser(t)
	get(t, c, ts.URL+"/setup")
	code := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, c, ts.URL+"/setup", url.Values{"code": {code}, "username": {"op"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)

	if _, body := get(t, c, ts.URL+"/runs"); !strings.Contains(body, "No runs recorded") {
		t.Fatalf("empty runs page:\n%s", body)
	}
	ctx := context.Background()
	for _, x := range []*store.Event{
		ev(store.EventToolCall, "laptop", "researcher", "research_topic", "", "", 1000, params("research solar")),
		ev(store.EventPermissionRequested, "laptop", "researcher", "research_topic", "", "", 1001, nil),
		ev(store.EventPermissionGranted, "laptop", "researcher", "research_topic", "sess_r", "", 1002, nil),
		ev(store.EventToolCall, "agent:researcher", "mailer", "send_email", "", "sess_r", 1003, params("To: bob")),
		ev(store.EventPermissionRequested, "agent:researcher", "mailer", "send_email", "", "sess_r", 1004, func(e *store.Event) { e.Scopes = []string{"mail:send"} }),
	} {
		x.ID = "evt_" + strconv.FormatInt(x.CreatedAt, 10)
		x.UserID = e.operator
		if err := e.st.AppendEvent(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	_, body := get(t, c, ts.URL+"/runs")
	if !strings.Contains(body, "research_topic: research solar") || !strings.Contains(body, "waiting for your approval") || !strings.Contains(body, "/runs/sess_r") {
		t.Fatalf("runs list:\n%s", body)
	}
	// the cards live inside the list's polling container; without hx-disinherit they would
	// inherit its hx-select and a click would swap an empty selection into the workspace
	if !strings.Contains(body, `hx-disinherit="*"`) {
		t.Error("runs list container must stop its htmx attributes from being inherited by the cards")
	}
	_, body = get(t, c, ts.URL+"/runs/sess_r")
	for _, want := range []string{"<svg", "may it use mailer?", "run-pending", "mail:send", "To: bob", `id="rkn"`} {
		if !strings.Contains(body, want) {
			t.Errorf("run page missing %q", want)
		}
	}
	sig := regexp.MustCompile(`id="rkn" name="known" value="([^"]+)"`).FindStringSubmatch(body)[1]
	res, err := c.Get(ts.URL + "/runs/sess_r/diagram?known=" + url.QueryEscape(sig))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("unchanged diagram poll = %d, want 204", res.StatusCode)
	}
	if _, body := get(t, c, ts.URL+"/runs/sess_r/diagram?known=stale"); !strings.Contains(body, "<svg") {
		t.Error("changed diagram poll did not re-render")
	}
	if _, body := get(t, c, ts.URL+"/runs/sess_nope"); !strings.Contains(body, "No run under") {
		t.Error("unknown run page")
	}
}

// Two root sessions on the same client connection — "research it", then a direct "email it"
// to another target — are one conversation, so one run.
func TestBuildRunsGroupsAConversation(t *testing.T) {
	conn := func(id string) func(*store.Event) { return func(e *store.Event) { e.ConnID = id } }
	both := func(id string, extra func(*store.Event)) func(*store.Event) {
		return func(e *store.Event) { e.ConnID = id; extra(e) }
	}
	runs := buildRuns([]*store.Event{
		ev(store.EventToolCall, "pi", "researcher", "research_topic", "", "", 1, both("c1", params("go"))),
		ev(store.EventPermissionGranted, "pi", "researcher", "research_topic", "sess_r", "", 2, conn("c1")),
		ev(store.EventToolResponse, "pi", "researcher", "research_topic", "sess_r", "", 3, both("c1", result("Go is…"))),
		ev(store.EventToolCall, "pi", "mailer", "send_email", "", "", 4, both("c1", params("To: bob"))),
		ev(store.EventPermissionGranted, "pi", "mailer", "send_email", "sess_m", "", 5, conn("c1")),
		ev(store.EventToolResponse, "pi", "mailer", "send_email", "sess_m", "", 6, both("c1", result("sent"))),
		// another conversation entirely
		ev(store.EventPermissionGranted, "pi", "researcher", "research_topic", "sess_other", "", 7, conn("c2")),
	})
	if len(runs) != 2 {
		t.Fatalf("got %d runs, want 2 (one per conversation)", len(runs))
	}
	var conv *run
	for _, r := range runs {
		if r.Root == "sess_r" {
			conv = r
		}
	}
	if conv == nil {
		t.Fatal("conversation run missing")
	}
	var names []string
	for _, p := range conv.Participants {
		names = append(names, p.Name)
	}
	if strings.Join(names, " ") != "you pi researcher mailer" || conv.Status != "done" {
		t.Errorf("conversation run = %v status %s", names, conv.Status)
	}
	// events from before the connection was recorded still group per root session
	old := buildRuns([]*store.Event{
		ev(store.EventPermissionGranted, "pi", "researcher", "", "s1", "", 1, nil),
		ev(store.EventPermissionGranted, "pi", "mailer", "", "s2", "", 2, nil),
	})
	if len(old) != 2 {
		t.Errorf("legacy events without a connection: %d runs, want 2", len(old))
	}
}

// Access lives on the server and in one relationship map: the Access tab sets the callee
// gate and the callers as edges, an agent's "what it can use" sets the caller gate and edges,
// both applied live; an agent's own keys live on its Agent keys tab and stay off the Keys
// page; remembered approvals are keyed by the agent, not its key.
func TestAccessTabAndAgentKeys(t *testing.T) {
	ts, e, logs := newDashboard(t)
	c := browser(t)
	get(t, c, ts.URL+"/setup")
	code := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, c, ts.URL+"/setup", url.Values{"code": {code}, "username": {"op"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)
	ctx := context.Background()
	e.st.PutAdapter(ctx, &store.AdapterDoc{ID: "gh", Name: "gh", Doc: []byte(`{"vendor":"gh"}`)})
	e.st.PutTarget(ctx, &store.Target{ID: "gh", Name: "GitHub", Kind: "mcp", Endpoint: "http://gh/mcp", AdapterID: "gh", Owner: e.operator, Enabled: true})
	e.st.PutTarget(ctx, &store.Target{ID: "planner", Name: "Planner", Kind: "a2a", Endpoint: "http://planner", AdapterID: "gh", Owner: e.operator, Enabled: true})
	e.st.PutTarget(ctx, &store.Target{ID: "weather", Name: "Weather", Kind: "a2a", Endpoint: "http://weather", AdapterID: "gh", Owner: e.operator, Enabled: true})

	_, body := get(t, c, ts.URL+"/targets/gh/access")
	if !strings.Contains(body, "Agents and GitHub") || !strings.Contains(body, "Seen by") || !strings.Contains(body, `/targets/planner/access`) {
		t.Fatalf("access tab lacks the lock form or the derived seen-by list:\n%s", body[:min(len(body), 800)])
	}
	if strings.Contains(body, "Agent keys") || strings.Contains(body, "What GitHub can use") || strings.Contains(body, `name="callers"`) {
		t.Fatal("an MCP server has no Agent keys tab, no exposure list, and no editable callers")
	}
	if !strings.Contains(body, "access-graph-svg") || !strings.Contains(body, ">Planner<") || !strings.Contains(body, ">You<") {
		t.Fatalf("reach diagram missing its boxes:\n%s", body[:min(len(body), 800)])
	}
	// the lock and consent mode are saved on the server
	_, body = post(t, c, ts.URL+"/targets/gh/access", url.Values{"audience": {"humans"}, "consent": {"remember"}}, true)
	if !strings.Contains(body, "Access saved") || !strings.Contains(body, "locked") {
		t.Fatalf("access not saved:\n%s", body[:min(len(body), 400)])
	}
	gh, _ := e.st.GetTarget(ctx, "gh")
	if gh.Audience != store.AudienceHumans || gh.Consent != store.ConsentRemember {
		t.Fatalf("stored access = %+v", gh)
	}
	post(t, c, ts.URL+"/targets/gh/access", url.Values{"audience": {""}, "consent": {"remember"}}, true)
	// the map is authored on the agent: its exposure list, with the edges as ticks
	_, body = get(t, c, ts.URL+"/targets/planner/access")
	if !strings.Contains(body, "What Planner can use") || !strings.Contains(body, `name="uses_targets" value="gh"`) {
		t.Fatalf("planner's exposure list must offer gh:\n%s", body[:min(len(body), 1200)])
	}
	if _, body := post(t, c, ts.URL+"/targets/planner/uses", url.Values{"uses": {"listed"}, "uses_targets": {"nobody"}}, true); !strings.Contains(body, "no target") {
		t.Fatalf("an unknown target must be refused:\n%s", body[:min(len(body), 400)])
	}
	post(t, c, ts.URL+"/targets/planner/uses", url.Values{"uses": {"listed"}, "uses_targets": {"gh"}}, true)
	planner, _ := e.st.GetTarget(ctx, "planner")
	if planner.Uses != store.UsesListed {
		t.Fatalf("exposure not stored: %+v", planner)
	}
	if _, err := e.st.GetRelation(ctx, "planner", "gh"); err != nil {
		t.Fatal("ticking gh must create the edge planner → gh")
	}
	gh, _ = e.st.GetTarget(ctx, "gh")
	pk := &store.AgentKey{ID: "akey_pl", AgentTargetID: "planner"}
	weather, _ := e.st.GetTarget(ctx, "weather")
	if !store.Visible(ctx, e.st, pk, gh) || store.Visible(ctx, e.st, pk, weather) {
		t.Fatal("planner must see gh (listed) and not weather (not listed)")
	}
	// the server's page shows the result: seen by the planner, and only it
	if _, body := get(t, c, ts.URL+"/targets/gh/access"); !strings.Contains(body, `/targets/planner/access`) {
		t.Fatalf("gh must list the planner under seen by:\n%s", body[:min(len(body), 800)])
	}
	if _, body := get(t, c, ts.URL+"/targets/weather/access"); !strings.Contains(body, "No agent sees it right now") {
		t.Fatalf("weather is seen by nobody once the planner is listed elsewhere:\n%s", body[:min(len(body), 800)])
	}
	// unticking removes the edge
	post(t, c, ts.URL+"/targets/planner/uses", url.Values{"uses": {"listed"}}, true)
	if _, err := e.st.GetRelation(ctx, "planner", "gh"); err == nil {
		t.Fatal("unticking must remove the edge")
	}
	if _, body := get(t, c, ts.URL+"/relationships"); !strings.Contains(body, "Relationships") || !strings.Contains(body, "access-graph-svg") {
		t.Fatalf("relationships page:\n%s", body[:min(len(body), 400)])
	}

	// the agent's keys: minted on its tab, off the Keys page
	_, body = post(t, c, ts.URL+"/targets/planner/keys", url.Values{"name": {"planner prod"}}, true)
	if !strings.Contains(body, "new key") || !strings.Contains(body, "dgk_") {
		t.Fatalf("agent key not minted on the agent's tab:\n%s", body[:min(len(body), 600)])
	}
	keys, _ := e.st.ListAgentKeys(ctx, e.operator)
	var kid string
	for _, k := range keys {
		if k.AgentTargetID == "planner" {
			kid = k.ID
		}
	}
	if kid == "" {
		t.Fatal("minted key is not issued to the planner")
	}
	if _, body := get(t, c, ts.URL+"/keys"); strings.Contains(body, "planner prod") {
		t.Fatal("an agent's key must not be listed on the Keys page")
	}
	// remembered by the agent's id: the row names the agent, and forget takes the id
	e.st.PutRemembered(ctx, &store.Remembered{Caller: "planner", TargetID: "gh", Scopes: []string{"repo:read"}, Reason: "test"})
	if _, body := get(t, c, ts.URL+"/targets/gh/access"); !strings.Contains(body, "agent Planner") || !strings.Contains(body, "repo:read") {
		t.Fatalf("remembered row missing:\n%s", body[:min(len(body), 600)])
	}
	post(t, c, ts.URL+"/targets/gh/remembered/planner/forget", nil, true)
	if _, err := e.st.GetRemembered(ctx, "planner", "gh"); err == nil {
		t.Fatal("forget did not remove the row")
	}
}

// fakeAgent is a minimal A2A agent for the playground test: a card with one skill and an
// example, and message/send answering with a message.
func fakeAgent(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(a2a.Card{Name: "Planner", URL: srv.URL + "/", Skills: []a2a.Skill{{ID: "plan_trip", Name: "Plan a trip", Description: "Plans a trip.", Examples: []string{"plan a trip to Lisbon"}}}})
	})
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Params struct {
				Message a2a.Message `json:"message"`
			} `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		reply := a2a.Message{Kind: "message", Role: "agent", MessageID: "r1", Parts: []a2a.Part{a2a.TextPart("itinerary for: " + a2a.PartsText(req.Params.Message.Parts))}}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": reply})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// The playground runs an agent as the operator's own client: the page offers the card's
// skills with the example prefilled, Run sends the message through the guarded A2A path and
// parks the person on a waiting page that turns into the live run once its first event is
// logged, and the run is listed as the playground's.
func TestPlayground(t *testing.T) {
	t.Setenv("DELEGENT_AUTOGRANT", "1") // the plumbing, not the consent dialog, is under test
	ts, e, logs := newDashboard(t)
	c := browser(t)
	get(t, c, ts.URL+"/setup")
	code := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, c, ts.URL+"/setup", url.Values{"code": {code}, "username": {"op"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)
	agent := fakeAgent(t)
	post(t, c, ts.URL+"/targets", url.Values{"name": {"planner"}, "kind": {"a2a"}, "endpoint": {agent.URL}, "credential": {"planner-secret"}}, true)
	if _, err := e.st.GetTarget(context.Background(), "planner"); err != nil {
		t.Fatalf("planner not registered: %v", err)
	}

	_, body := get(t, c, ts.URL+"/play/planner")
	if !strings.Contains(body, "Run planner") || !strings.Contains(body, `value="plan_trip"`) || !strings.Contains(body, "plan a trip to Lisbon</textarea>") {
		t.Fatalf("playground page lacks the skill or the prefilled example:\n%s", body[:min(len(body), 1200)])
	}
	// a freshly drafted skill is unclassified: the page says so, and classifying clears it
	if !strings.Contains(body, "Not classified yet: plan_trip") {
		t.Fatalf("playground must warn about unclassified skills:\n%s", body[:min(len(body), 1200)])
	}
	post(t, c, ts.URL+"/targets/planner/policy", url.Values{"tool": {"plan_trip", "get_task"}, "effect.plan_trip": {"read"}, "scope.plan_trip": {"trip:read"}, "effect.get_task": {"read"}, "scope.get_task": {"trip:read"}}, true)
	if _, body := get(t, c, ts.URL+"/play/planner"); strings.Contains(body, "Not classified yet") {
		t.Fatal("classified skills must not be flagged")
	}
	if _, body := get(t, c, ts.URL+"/targets/planner/access"); !strings.Contains(body, `href="/play/planner"`) {
		t.Fatal("the agent's page must offer Run")
	}
	// an empty message is refused on the page
	if _, body := post(t, c, ts.URL+"/play/planner", url.Values{"skill": {"plan_trip"}, "message": {" "}}, true); !strings.Contains(body, "write the message") {
		t.Fatalf("empty message must be refused:\n%s", body[:min(len(body), 400)])
	}
	res, _ := post(t, c, ts.URL+"/play/planner", url.Values{"skill": {"plan_trip"}, "message": {"plan a trip to Oslo"}}, true)
	wait := res.Header.Get("HX-Redirect")
	if !strings.HasPrefix(wait, "/play/planner/") {
		t.Fatalf("Run must send the person to the waiting page, got %q", wait)
	}
	// the waiting page becomes the live run once the first event is logged
	var runBody string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, runBody = get(t, c, ts.URL+wait) // the client follows the redirect to /runs/<root>
		if strings.Contains(runBody, "RUN DETAILS") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(runBody, "RUN DETAILS") || !strings.Contains(runBody, "plan a trip to Oslo") {
		at := max(strings.Index(runBody, "PLAYGROUND"), 0)
		t.Fatalf("waiting page never turned into the run:\n%s\n--- logs ---\n%s", runBody[at:min(len(runBody), at+900)], logs.String())
	}
	if _, body := get(t, c, ts.URL+"/runs"); !strings.Contains(body, "playground") {
		t.Fatalf("the run must be listed as the playground's:\n%s", body[:min(len(body), 800)])
	}
	// the answer came back through the guarded path and is on the run's timeline
	root := regexp.MustCompile(`data-run-flow="/runs/([^/"]+)/state"`).FindStringSubmatch(runBody)
	if root == nil {
		t.Fatalf("run page carries no root:\n%s", runBody[:min(len(runBody), 600)])
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, body := get(t, c, ts.URL+"/runs/"+root[1]+"/diagram"); strings.Contains(body, "itinerary for: plan a trip to Oslo") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the agent's answer never reached the run")
}

// A key minted in the dashboard keeps its own name ("pm prod") and is tied to its agent only
// by AgentTargetID: its calls must land on the agent's lifeline, so the agent is one
// participant and not two. A person's key with the same prefix but another name is untouched.
func TestAgentKeyNamedFreelyJoinsItsAgent(t *testing.T) {
	withPrefix := func(p string) func(*store.Event) { return func(e *store.Event) { e.KeyPrefix = p } }
	events := []*store.Event{
		ev(store.EventToolCall, "playground", "pm", "plan_project", "", "", 1, params("plan a site")),
		ev(store.EventPermissionGranted, "playground", "pm", "plan_project", "sess_root", "", 2, nil),
		ev(store.EventToolCall, "playground", "pm", "plan_project", "sess_root", "", 3, params("plan a site")),
		ev(store.EventToolCall, "pm prod", "linear", "save_project", "", "sess_root", 4, withPrefix("dgk_pm01")),
		ev(store.EventPermissionGranted, "pm prod", "linear", "", "sess_child", "sess_root", 4, nil), // a console decision: name, no prefix
		ev(store.EventToolResponse, "pm prod", "linear", "save_project", "sess_child", "sess_root", 5, func(e *store.Event) { e.KeyPrefix = "dgk_pm01"; result("P-1")(e) }),
		ev(store.EventToolCall, "laptop", "linear", "list_teams", "", "", 6, withPrefix("dgk_pm01")),
	}
	keys := []*store.AgentKey{
		{Prefix: "dgk_pm01", Name: "pm prod", AgentTargetID: "pm"},
		{Prefix: "dgk_pm01", Name: "laptop"}, // a person's key: not an agent's
	}
	// A name shared by two keys is never matched on the name alone.
	shared := []*store.Event{ev(store.EventPermissionGranted, "twin", "linear", "", "s", "", 1, nil)}
	attributeAgentKeys(shared, []*store.AgentKey{{Prefix: "a", Name: "twin", AgentTargetID: "pm"}, {Prefix: "b", Name: "twin"}})
	if shared[0].KeyName != "twin" {
		t.Fatalf("an ambiguous name was attributed: %q", shared[0].KeyName)
	}
	attributeAgentKeys(events, keys)
	for _, i := range []int{3, 4, 5} {
		if events[i].KeyName != "agent:pm" {
			t.Fatalf("row %d: the agent's key was not attributed: %q", i, events[i].KeyName)
		}
	}
	if events[6].KeyName != "laptop" {
		t.Fatalf("a person's key was relabelled: %q", events[6].KeyName)
	}
	runs := buildRuns(events)
	if len(runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(runs))
	}
	var names []string
	for _, p := range runs[0].Participants {
		names = append(names, p.Name)
	}
	if got := strings.Join(names, ","); got != "you,playground,pm,linear" {
		t.Errorf("participants = %s, want you,playground,pm,linear (pm once, no 'pm prod')", got)
	}
}

// Stopping a run from its page: the page offers it while the run is going, the stop revokes
// every session in it and is recorded, and afterwards the run reads "stopped" with nothing
// left to stop. Another operator's run cannot be stopped.
func TestStopRunFromTheDashboard(t *testing.T) {
	ts, e, logs := newDashboard(t)
	c := browser(t)
	get(t, c, ts.URL+"/setup")
	code := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, c, ts.URL+"/setup", url.Values{"code": {code}, "username": {"op"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)

	ctx := context.Background()
	for _, s := range []*store.Session{
		{Handle: "sess_root", Principal: e.operator},
		{Handle: "sess_hop", Principal: e.operator, ParentHandle: "sess_root"},
		{Handle: "sess_theirs", Principal: "usr_someone_else"},
	} {
		if err := e.st.PutSession(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UnixMilli()
	for _, ev := range []*store.Event{
		{Type: store.EventToolCall, KeyName: "playground", TargetID: "pm", Tool: "plan_project", SessionHandle: "sess_root", CreatedAt: now},
		{Type: store.EventToolCall, KeyName: "agent:pm", TargetID: "engineer", Tool: "build_feature", SessionHandle: "sess_hop", ParentHandle: "sess_root", CreatedAt: now + 1},
	} {
		ev.UserID = e.operator
		if err := e.st.AppendEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}

	_, page := get(t, c, ts.URL+"/runs/sess_root")
	if !strings.Contains(page, `hx-post="/runs/sess_root/stop"`) {
		t.Fatal("a running run should offer Stop run")
	}
	_, page = post(t, c, ts.URL+"/runs/sess_root/stop", url.Values{}, true)
	if !strings.Contains(page, "Run stopped. 2 sessions revoked") {
		t.Errorf("no stop notice in the page:\n%s", excerptAround(page, "run-notice"))
	}
	if strings.Contains(page, `hx-post="/runs/sess_root/stop"`) {
		t.Error("a stopped run should not offer Stop run again")
	}
	for _, h := range []string{"sess_root", "sess_hop"} {
		if ss, _ := e.st.GetSession(ctx, h); ss.RevokedAt == 0 {
			t.Errorf("%s still live after the stop", h)
		}
	}
	x := findTestRun(t, ts, c, "sess_root")
	if x.Status != "stopped" || x.StatusTone != "bad" {
		t.Errorf("status = %q %q, want stopped", x.Status, x.StatusTone)
	}

	_, page = post(t, c, ts.URL+"/runs/sess_theirs/stop", url.Values{}, true)
	if ss, _ := e.st.GetSession(ctx, "sess_theirs"); ss.RevokedAt != 0 || !strings.Contains(page, "No run under") {
		t.Error("another operator's run was stopped")
	}
}

// findTestRun reads a run's live state the way the page polls it.
func findTestRun(t *testing.T, ts *httptest.Server, c *http.Client, root string) struct{ Status, StatusTone string } {
	t.Helper()
	res, err := c.Get(ts.URL + "/runs/" + root + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out struct {
		Status     string `json:"status"`
		StatusTone string `json:"status_tone"`
	}
	json.NewDecoder(res.Body).Decode(&out)
	return struct{ Status, StatusTone string }{out.Status, out.StatusTone}
}

func excerptAround(s, marker string) string {
	i := strings.Index(s, marker)
	if i < 0 {
		return "(" + marker + " not found)"
	}
	end := i + 300
	if end > len(s) {
		end = len(s)
	}
	return s[i:end]
}

// A reply that arrives after its run was stopped carries no session (it was revoked); it stays
// with its own run's connection and is not adopted by the next run of the same key and target.
func TestLateReplyStaysWithItsRun(t *testing.T) {
	onConn := func(c string) func(*store.Event) { return func(e *store.Event) { e.ConnID = c } }
	events := []*store.Event{
		ev(store.EventToolCall, "tester", "slow", "work", "sess_1", "", 1, onConn("c1")),
		ev(store.EventRunStopped, "", "", "", "sess_1", "", 2, nil),
		ev(store.EventToolResponse, "tester", "slow", "work", "", "", 3, func(e *store.Event) { e.ConnID = "c1"; result("canceled")(e) }),
		ev(store.EventToolCall, "tester", "slow", "work", "sess_2", "", 4, onConn("c2")),
	}
	runs := buildRuns(events)
	if len(runs) != 2 {
		t.Fatalf("got %d runs, want 2", len(runs))
	}
	byRoot := map[string]*run{}
	for _, r := range runs {
		byRoot[r.Root] = r
	}
	if n := len(byRoot["sess_1"].events); n != 3 {
		t.Errorf("the stopped run has %d events, want 3 (its late reply included)", n)
	}
	if n := len(byRoot["sess_2"].events); n != 1 {
		t.Errorf("the next run adopted %d events, want only its own 1", n)
	}
	if byRoot["sess_1"].Status != "stopped" {
		t.Errorf("status = %q", byRoot["sess_1"].Status)
	}
}

// The unfinished agent tasks of a run are read from its log: the latest reply for each task
// decides, so a task that later completed is left out.
func TestUnfinishedTasksFromTheLog(t *testing.T) {
	reply := func(taskID, state string) func(*store.Event) {
		return func(e *store.Event) {
			e.Result, _ = json.Marshal(map[string]any{"structuredContent": map[string]any{"task_id": taskID, "state": state}})
		}
	}
	x := &run{events: []*store.Event{
		ev(store.EventToolResponse, "agent:pm", "engineer", "build_feature", "sess_hop", "sess_root", 1, reply("t1", "working")),
		ev(store.EventToolResponse, "agent:pm", "designer", "define", "sess_hop2", "sess_root", 2, reply("t2", "working")),
		ev(store.EventToolResponse, "agent:pm", "designer", "get_task", "sess_hop2", "sess_root", 3, reply("t2", "completed")),
		ev(store.EventToolResponse, "agent:pm", "linear", "save_issue", "sess_hop3", "sess_root", 4, result("TES-1")),
	}}
	got := unfinishedTasks(x)
	if len(got) != 1 || got[0].Target != "engineer" || got[0].TaskID != "t1" || got[0].Session != "sess_hop" {
		t.Errorf("unfinished = %+v", got)
	}
}
