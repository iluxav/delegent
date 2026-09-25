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

	"delegent.dev/gateway/a2a"
	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/provision"
	"delegent.dev/gateway/rootkeys"
	"delegent.dev/gateway/secretstore"
	"delegent.dev/gateway/store"
)

// leafAgent is a real (tiny) A2A agent: one skill, answers with a completed task, and records
// the session header each call arrived with.
func leafAgent(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var sessions []string
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(a2a.Card{Name: "Leaf", URL: srv.URL + "/a2a", Version: "1",
			Capabilities:    a2a.Capabilities{Streaming: true},
			Skills:          []a2a.Skill{{ID: "work", Name: "Work", Description: "Does the work.", Tags: []string{"read"}}},
			SecuritySchemes: map[string]a2a.SecurityScheme{"bearer": {Type: "http", Scheme: "bearer"}}})
	})
	mux.HandleFunc("POST /a2a", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer leaf-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		sessions = append(sessions, r.Header.Get(a2a.SessionHeader))
		mu.Unlock()
		var req struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
			Params struct {
				Message a2a.Message `json:"message"`
				ID      string      `json:"id"`
			} `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		text := a2a.PartsText(req.Params.Message.Parts)
		if req.Method == "tasks/get" {
			text = "(status of " + req.Params.ID + ")"
		}
		task := a2a.Task{Kind: "task", ID: "t-leaf", ContextID: "ctx-leaf", Status: a2a.TaskStatus{State: a2a.StateCompleted},
			Artifacts: []a2a.Artifact{{ArtifactID: "a", Parts: []a2a.Part{a2a.TextPart("worked on: " + text)}}}}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": task})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), sessions...) }
}

// delegentWithLeaf provisions the leaf agent as an A2A target on an in-memory gateway (auth
// off) and mounts the A2A surface.
func delegentWithLeaf(t *testing.T, leaf *httptest.Server) (*httptest.Server, *Registry) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemStore()
	sealer, _ := keyring.NewAESSealer([]byte("delegent-dev-master-key-32-bytes"))
	if err := st.PutUser(ctx, &store.User{ID: "usr_op"}); err != nil {
		t.Fatal(err)
	}
	if _, err := rootkeys.New(st, sealer).Ensure(ctx, "usr_op"); err != nil {
		t.Fatal(err)
	}
	draft, _, err := a2a.Introspect(ctx, leaf.URL, "leaf-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.CreateTarget(ctx, st, secretstore.NewDB(st, sealer), provision.CreateTargetInput{
		ID: "leaf", Name: "Leaf", Kind: TargetKindA2A, Endpoint: leaf.URL, Credential: "leaf-secret", Owner: "usr_op", Tools: provision.FromDraft(draft.Tools),
	}); err != nil {
		t.Fatal(err)
	}
	reg := NewRegistry(st, sealer)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /a2a", reg.ServeA2AIndex)
	mux.HandleFunc("/a2a/{target}", reg.ServeA2A)
	mux.HandleFunc("/a2a/{target}/{rest...}", reg.ServeA2A)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, reg
}

// An A2A client pointed at Delegent instead of the agent: the rewritten card, then
// message/send through the guarded path (auto-granted here) to the real agent, which sees the
// caller's Delegent session, never the caller.
func TestA2ASurfaceProxiesAnAgent(t *testing.T) {
	t.Setenv("DELEGENT_AUTOGRANT", "1")
	leaf, sessions := leafAgent(t)
	dg, _ := delegentWithLeaf(t, leaf)

	card, err := a2a.FetchCard(context.Background(), dg.URL+"/a2a/leaf", "")
	if err != nil {
		t.Fatal(err)
	}
	if card.URL != dg.URL+"/a2a/leaf" || card.Capabilities.Streaming || card.SecuritySchemes["delegent"].Scheme != "bearer" || len(card.Skills) != 1 {
		t.Fatalf("rewritten card = %+v", card)
	}
	if !strings.Contains(card.Description, "via Delegent") {
		t.Errorf("card description = %q", card.Description)
	}

	c := &a2a.Client{URL: card.URL}
	res, err := c.Send(context.Background(), "hello leaf", a2a.SendOpts{Metadata: map[string]any{"intent": "test"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.State != a2a.StateCompleted || !strings.Contains(res.Text, "worked on: hello leaf") || res.TaskID != "t-leaf" {
		t.Fatalf("result = %+v", res)
	}
	got, err := c.GetTask(context.Background(), "t-leaf", "")
	if err != nil || got.State != a2a.StateCompleted {
		t.Fatalf("tasks/get through delegent: %+v %v", got, err)
	}
	if s := sessions(); len(s) == 0 || s[0] == "" || !strings.HasPrefix(s[0], "sess_") {
		t.Errorf("the agent should have received the caller's Delegent session, got %v", s)
	}
	if _, err := c.Send(context.Background(), "x", a2a.SendOpts{NoWait: true, Metadata: map[string]any{"skill": "nope"}}); err == nil {
		t.Error("an unknown skill must be refused")
	}

	res2, err := http.Get(dg.URL + "/a2a")
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	var idx struct {
		Agents []struct{ ID, URL string } `json:"agents"`
	}
	json.NewDecoder(res2.Body).Decode(&idx)
	if len(idx.Agents) != 1 || idx.Agents[0].ID != "leaf" || idx.Agents[0].URL != dg.URL+"/a2a/leaf" {
		t.Errorf("index = %+v", idx)
	}
}

// With a human in the loop: message/send comes back as an auth-required task while the ask is
// parked, and tasks/get on that id yields the real result once the operator approved.
func TestA2ASurfaceParksOnConsent(t *testing.T) {
	t.Setenv("DELEGENT_AUTOGRANT", "")
	t.Setenv("DELEGENT_A2A_CONSENT_WAIT", "100ms")
	leaf, _ := leafAgent(t)
	dg, reg := delegentWithLeaf(t, leaf)

	c := &a2a.Client{URL: dg.URL + "/a2a/leaf"}
	res, err := c.Send(context.Background(), "hello", a2a.SendOpts{NoWait: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.State != a2a.StateAuthRequired || !strings.HasPrefix(res.TaskID, pendingTaskPrefix) {
		t.Fatalf("expected an auth-required pending task, got %+v", res)
	}
	consentID := strings.TrimPrefix(res.TaskID, pendingTaskPrefix)

	// still pending: same answer
	again, err := c.GetTask(context.Background(), res.TaskID, "")
	if err != nil || again.State != a2a.StateAuthRequired {
		t.Fatalf("pending poll = %+v %v", again, err)
	}

	// the operator approves in the console
	if ok, err := reg.ResolveConsent("usr_op", consentID, []string{"data:read", "mcp:connect"}, 60, 1); err != nil || !ok {
		t.Fatalf("resolve consent: ok=%v err=%v", ok, err)
	}
	var done *a2a.Result
	for i := 0; i < 20; i++ {
		done, err = c.GetTask(context.Background(), res.TaskID, "")
		if err != nil {
			t.Fatal(err)
		}
		if done.State == a2a.StateCompleted {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if done.State != a2a.StateCompleted || !strings.Contains(done.Text, "worked on: hello") || done.TaskID != res.TaskID {
		t.Fatalf("after approval = %+v", done)
	}
	// and again: the same answer, no second run
	final, _ := c.GetTask(context.Background(), res.TaskID, "")
	if final.State != a2a.StateCompleted {
		t.Errorf("repeat poll = %+v", final)
	}
}
