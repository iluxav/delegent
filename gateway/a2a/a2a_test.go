package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeAgent is a minimal A2A agent: a card at the well-known path, and a JSON-RPC endpoint
// whose message/send returns a working task that completes after `polls` tasks/get calls.
type fakeAgent struct {
	mu       sync.Mutex
	polls    int
	seen     []http.Header
	metadata map[string]any
	immed    bool // reply with a plain message instead of a task
	secret   string
}

func (f *fakeAgent) handler(base string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Card{
			Name: "Researcher", Description: "finds things", URL: base + "/rpc", Version: "1.0",
			Skills:          []Skill{{ID: "research_topic", Name: "Research a topic", Description: "Gathers material on a topic.", Tags: []string{"read"}, Examples: []string{"research solar panels"}}},
			SecuritySchemes: map[string]SecurityScheme{"bearer": {Type: "http", Scheme: "bearer"}},
		})
	})
	mux.HandleFunc("POST /rpc", func(w http.ResponseWriter, r *http.Request) {
		if f.secret != "" && r.Header.Get("Authorization") != "Bearer "+f.secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req rpcRequest
		json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.seen = append(f.seen, r.Header.Clone())
		f.mu.Unlock()
		var result any
		switch req.Method {
		case "message/send":
			p, _ := json.Marshal(req.Params)
			var params struct {
				Message Message `json:"message"`
			}
			json.Unmarshal(p, &params)
			f.mu.Lock()
			f.metadata = params.Message.Metadata
			f.mu.Unlock()
			if f.immed {
				result = Message{Kind: "message", Role: "agent", Parts: []Part{TextPart("hi: " + PartsText(params.Message.Parts))}, MessageID: "m1", ContextID: "ctx1"}
			} else {
				result = Task{Kind: "task", ID: "t1", ContextID: "ctx1", Status: TaskStatus{State: StateWorking, Message: &Message{Parts: []Part{TextPart("looking")}}}}
			}
		case "tasks/get":
			f.mu.Lock()
			f.polls++
			n := f.polls
			f.mu.Unlock()
			if n < 2 {
				result = Task{Kind: "task", ID: "t1", ContextID: "ctx1", Status: TaskStatus{State: StateWorking, Message: &Message{Parts: []Part{TextPart("still looking")}}}}
			} else {
				result = Task{Kind: "task", ID: "t1", ContextID: "ctx1", Status: TaskStatus{State: StateCompleted},
					Artifacts: []Artifact{{ArtifactID: "a1", Name: "summary", Parts: []Part{TextPart("done"), {Kind: "data", Data: map[string]any{"n": 1}}}}}}
			}
		default:
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32601, "message": "no such method"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	})
	return mux
}

func startAgent(t *testing.T, f *fakeAgent) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.handler(srv.URL).ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchCardAndDraft(t *testing.T) {
	f := &fakeAgent{}
	srv := startAgent(t, f)
	for _, ep := range []string{srv.URL, srv.URL + "/", srv.URL + "/.well-known/agent-card.json", srv.URL + "/some/path"} {
		card, err := FetchCard(context.Background(), ep, "")
		if err != nil {
			t.Fatalf("FetchCard(%s): %v", ep, err)
		}
		if card.Name != "Researcher" || card.URL != srv.URL+"/rpc" || len(card.Skills) != 1 {
			t.Errorf("FetchCard(%s) = %+v", ep, card)
		}
		if card.CredentialKind() != "static_bearer" {
			t.Errorf("credential kind = %q", card.CredentialKind())
		}
	}
	res, card, err := Introspect(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 2 {
		t.Fatalf("drafted %d tools, want the skill + get_task", len(res.Tools))
	}
	if d := res.Tools[0]; d.Name != "research_topic" || d.Effect != "read" || d.Scope != "data:read" || d.Unknown {
		t.Errorf("skill draft = %+v", d)
	}
	if !strings.Contains(res.Tools[0].Description, "research solar panels") {
		t.Errorf("skill description lost its example: %q", res.Tools[0].Description)
	}
	if d := res.Tools[1]; d.Name != TaskTool || d.Effect != "read" {
		t.Errorf("get_task draft = %+v", d)
	}
	if card.Skills[0].ID != "research_topic" {
		t.Errorf("card = %+v", card)
	}
}

func TestSendPollsTaskAndCarriesSession(t *testing.T) {
	f := &fakeAgent{secret: "s3cret"}
	srv := startAgent(t, f)
	c := &Client{URL: srv.URL + "/rpc", Credential: "s3cret", PollInterval: 1}
	var progress []string
	res, err := c.Send(context.Background(), "research solar", SendOpts{Skill: "research_topic", Session: "sess_abc", Progress: func(s string) { progress = append(progress, s) }})
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateCompleted || res.TaskID != "t1" || res.ContextID != "ctx1" {
		t.Errorf("result = %+v", res)
	}
	if !strings.Contains(res.Text, "summary: done") || !strings.Contains(res.Text, `{"n":1}`) {
		t.Errorf("text = %q", res.Text)
	}
	if len(progress) < 2 || !strings.Contains(progress[0], "working") {
		t.Errorf("progress = %v", progress)
	}
	for _, h := range f.seen {
		if h.Get(SessionHeader) != "sess_abc" {
			t.Errorf("a request went out without the session header: %v", h)
		}
		if h.Get("Authorization") != "Bearer s3cret" {
			t.Errorf("credential missing: %v", h)
		}
	}
	if f.metadata[SessionMetaKey] != "sess_abc" || f.metadata[SkillMetaKey] != "research_topic" {
		t.Errorf("message metadata = %v", f.metadata)
	}
}

func TestSendImmediateMessage(t *testing.T) {
	f := &fakeAgent{immed: true}
	srv := startAgent(t, f)
	c := &Client{URL: srv.URL + "/rpc"}
	res, err := c.Send(context.Background(), "hello", SendOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "" || res.Text != "hi: hello" || res.ContextID != "ctx1" || res.Message == nil {
		t.Errorf("result = %+v", res)
	}
}

func TestRPCErrorsSurface(t *testing.T) {
	f := &fakeAgent{secret: "x"}
	srv := startAgent(t, f)
	if _, err := (&Client{URL: srv.URL + "/rpc", Credential: "wrong"}).Send(context.Background(), "hi", SendOpts{}); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("bad credential: err = %v", err)
	}
	var raw json.RawMessage
	c := &Client{URL: srv.URL + "/rpc", Credential: "x"}
	if err := c.call(context.Background(), "tasks/resubscribe", nil, "", &raw); err == nil || !strings.Contains(err.Error(), "no such method") {
		t.Errorf("rpc error: %v", err)
	}
}

func TestNormaliseWithoutKind(t *testing.T) {
	r, err := normalise(json.RawMessage(`{"id":"t9","contextId":"c","status":{"state":"input-required","message":{"parts":[{"kind":"text","text":"which one?"}]}}}`))
	if err != nil || r.State != StateInputRequired || r.Text != "which one?" {
		t.Errorf("task without kind: %+v %v", r, err)
	}
	if _, err := normalise(json.RawMessage(`{"foo":1}`)); err == nil {
		t.Error("garbage accepted")
	}
}
