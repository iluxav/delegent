package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

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
