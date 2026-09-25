package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway/a2a"
	"delegent.dev/gateway/agentkey"
	"delegent.dev/gateway/store"
)

func TestConnKeyRoundTrip(t *testing.T) {
	if baseConn("c1") != "c1" || parentOfConn("c1") != "" {
		t.Error("plain key mangled")
	}
	k := "c1" + connKeySep + "sess_p"
	if baseConn(k) != "c1" || parentOfConn(k) != "sess_p" {
		t.Errorf("composite key split wrong: %q %q", baseConn(k), parentOfConn(k))
	}
}

// authedCtx runs a request with the given headers through the aggregate's bearer middleware
// over a store holding key k, and hands back the context the tool handlers would see.
func authedCtx(t *testing.T, st store.Store, token string, headers map[string]string) context.Context {
	t.Helper()
	var got context.Context
	h := auth.RequireBearerToken(makeUserVerifier(st), nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Context()
	}))
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || got == nil {
		t.Fatalf("auth middleware rejected the request: %d %s", rec.Code, rec.Body.String())
	}
	return got
}

func TestSessionHeaderBecomesLineage(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	st := g.st
	harness, hHash, _ := agentkey.New()
	agent, aHash, _ := agentkey.New()
	ctx := context.Background()
	st.PutAgentKey(ctx, &store.AgentKey{ID: "akey_h", UserID: "root:alice", Hash: hHash, Name: "laptop"})
	st.PutAgentKey(ctx, &store.AgentKey{ID: "akey_a", UserID: "root:alice", Hash: aHash, Name: "agent:researcher", AgentTargetID: "researcher"})

	// A harness with no header: a root call, keyed by its connection alone.
	hctx := authedCtx(t, st, harness, nil)
	if parentFromContext(hctx) != "" || g.connKey(hctx, "c1") != "c1" {
		t.Error("a header-less call must be parentless")
	}
	if name, label := g.callerName(hctx, ""); name != "laptop@mcp-remote (new connection)" || label != "laptop@mcp-remote" {
		t.Errorf("harness caller = %q / %q", name, label)
	}

	// The harness earns a session; the agent then calls back echoing it.
	parent, _, ok := g.br.GrantUnder("root:alice", "", []string{"mcp:connect", "files:read"}, "x", grantAll{}, g.lineageOf(hctx))
	if !ok {
		t.Fatal("root grant failed")
	}
	actx := authedCtx(t, st, agent, map[string]string{a2a.SessionHeader: parent})
	if parentFromContext(actx) != parent || agentTargetFromContext(actx) != "researcher" {
		t.Fatalf("token extra lost the header/agent target: %v", auth.TokenInfoFromContext(actx).Extra)
	}
	if got := g.connKey(actx, "c2"); got != "c2"+connKeySep+parent {
		t.Errorf("connKey = %q", got)
	}
	name, label := g.callerName(actx, "")
	if !strings.HasPrefix(name, "agent:researcher@mcp-remote (working under laptop@mcp-remote") || label != "agent:researcher@mcp-remote" {
		t.Errorf("agent caller = %q / %q", name, label)
	}
	child, msg, ok := g.br.GrantUnder("root:alice", "", []string{"mcp:connect", "files:read"}, "x", grantAll{}, g.lineageOf(actx))
	if !ok {
		t.Fatal(msg)
	}
	if got := g.br.AgentDisplayName(child); got != "laptop@mcp-remote→agent:researcher@mcp-remote" {
		t.Errorf("chain name = %q", got)
	}
	ev := g.eventBase(actx, "")
	if ev.ParentHandle != parent || ev.KeyName != "agent:researcher" {
		t.Errorf("event lineage = %+v", ev)
	}

	// The same agent key with NO header: parentless, and the prompt says so.
	pctx := authedCtx(t, st, agent, nil)
	if name, _ := g.callerName(pctx, ""); !strings.Contains(name, "no parent task given") {
		t.Errorf("parentless agent caller = %q", name)
	}

	// Caps/policy stashed at initialize under the raw connection id are found under the
	// composite key, so a parented call routes to the same consent channel.
	g.setCaps("c2", clientCaps{elicitation: true})
	if !g.capsOf("c2" + connKeySep + parent).elicitation {
		t.Error("caps lookup missed the composite key")
	}
}

// fakeA2A is the smallest agent the upstream can front: one skill, immediate replies that
// echo the session they were called under.
func fakeA2A(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(a2a.Card{Name: "Mailer", URL: srv.URL + "/a2a", Skills: []a2a.Skill{{ID: "send_email", Name: "Send email", Description: "Sends an email."}}})
	})
	mux.HandleFunc("POST /a2a", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     int64 `json:"id"`
			Params struct {
				Message a2a.Message `json:"message"`
			} `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		reply := a2a.Message{Kind: "message", Role: "agent", MessageID: "r1", ContextID: "ctx7",
			Parts: []a2a.Part{a2a.TextPart("sent (" + a2a.PartsText(req.Params.Message.Parts) + ") under " + r.Header.Get(a2a.SessionHeader))}}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": reply})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestA2AUpstreamToolsAndCall(t *testing.T) {
	srv := fakeA2A(t)
	up, err := newA2AUpstream(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	tools, _ := up.Tools(context.Background())
	if len(tools) != 2 || tools[0].Name != "send_email" || tools[1].Name != a2a.TaskTool {
		t.Fatalf("tools = %+v", tools)
	}
	res, err := up.Call(context.Background(), UpstreamCall{Name: "send_email", Args: map[string]any{"message": "hi bob"}, Session: "sess_42"})
	if err != nil {
		t.Fatal(err)
	}
	if txt := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(txt, "sent (hi bob) under sess_42") || !strings.Contains(txt, "context_id: ctx7") {
		t.Errorf("call text = %q", txt)
	}
	if r := mustText(up.Call(context.Background(), UpstreamCall{Name: "send_email", Args: map[string]any{}})); !strings.Contains(r, "needs a message") {
		t.Errorf("empty message: %q", r)
	}
	if r := mustText(up.Call(context.Background(), UpstreamCall{Name: "nope"})); !strings.Contains(r, "unknown skill") {
		t.Errorf("unknown skill: %q", r)
	}
}

func mustText(res *mcp.CallToolResult, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// A slow agent: the first call hands the task back within the wait budget instead of blocking,
// and a repeat of the same request attaches to the running task rather than starting another.
func TestA2AUpstreamHandsBackLongTasksAndDedupes(t *testing.T) {
	var sends, gets int
	var mu sync.Mutex
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(a2a.Card{Name: "Slow", URL: srv.URL + "/a2a", Skills: []a2a.Skill{{ID: "think", Name: "Think", Description: "Thinks for a long time."}}})
	})
	mux.HandleFunc("POST /a2a", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		if req.Method == "message/send" {
			sends++
		} else {
			gets++
		}
		done := gets >= 40
		mu.Unlock()
		state := a2a.StateWorking
		var arts []a2a.Artifact
		if done {
			state, arts = a2a.StateCompleted, []a2a.Artifact{{ArtifactID: "a", Parts: []a2a.Part{a2a.TextPart("thought")}}}
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": a2a.Task{Kind: "task", ID: "t1", ContextID: "c", Status: a2a.TaskStatus{State: state}, Artifacts: arts}})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	up, err := newA2AUpstream(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	up.client.PollInterval, up.client.PollTimeout = 2*time.Millisecond, 20*time.Millisecond
	first := mustText(up.Call(context.Background(), UpstreamCall{Name: "think", Args: map[string]any{"message": "hi"}, Session: "s"}))
	if !strings.Contains(first, "still working") || !strings.Contains(first, `get_task {task_id: "t1"}`) {
		t.Fatalf("first call should hand the task back with its id: %q", first)
	}
	// the client's retry of the same message: no second message/send
	second := mustText(up.Call(context.Background(), UpstreamCall{Name: "think", Args: map[string]any{"message": "hi"}, Session: "s"}))
	mu.Lock()
	n := sends
	mu.Unlock()
	if n != 1 {
		t.Errorf("a repeated request started %d tasks, want 1", n)
	}
	if !strings.Contains(second, "thought") && !strings.Contains(second, "still working") {
		t.Errorf("second call = %q", second)
	}
	// once the task completed, the request is forgotten: a fresh identical request is new work
	up.client.PollTimeout = time.Second
	mustText(up.Call(context.Background(), UpstreamCall{Name: "think", Args: map[string]any{"message": "hi"}, Session: "s"}))
	mustText(up.Call(context.Background(), UpstreamCall{Name: "think", Args: map[string]any{"message": "hi"}, Session: "s"}))
	mu.Lock()
	n = sends
	mu.Unlock()
	if n != 2 {
		t.Errorf("after completion a repeat should start anew: sends=%d, want 2", n)
	}
}

// get_task is a status check: a message tacked onto it does not reach the agent unless the
// task is actually waiting for input.
func TestA2AGetTaskNeverRestartsWork(t *testing.T) {
	var sends int
	var mu sync.Mutex
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(a2a.Card{Name: "W", URL: srv.URL + "/a2a", Skills: []a2a.Skill{{ID: "work", Name: "Work"}}})
	})
	mux.HandleFunc("POST /a2a", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		if req.Method == "message/send" {
			sends++
		}
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": a2a.Task{Kind: "task", ID: "t1", ContextID: "c", Status: a2a.TaskStatus{State: a2a.StateWorking}}})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	up, err := newA2AUpstream(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	up.client.PollInterval, up.client.PollTimeout = time.Millisecond, 5*time.Millisecond
	out := mustText(up.Call(context.Background(), UpstreamCall{Name: a2a.TaskTool, Args: map[string]any{"task_id": "t1", "message": "please check my task"}, Session: "s"}))
	mu.Lock()
	n := sends
	mu.Unlock()
	if n != 0 {
		t.Errorf("get_task with a message sent %d message(s) to a working task, want 0", n)
	}
	if !strings.Contains(out, "still working") {
		t.Errorf("status check = %q", out)
	}
}
