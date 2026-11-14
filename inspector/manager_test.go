package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestManagerRoundTrip drives a real streamable-HTTP MCP server through the manager the way
// the UI does: connect, list tools, call a tool that elicits, answer the elicitation from the
// pending list, and check the transcript saw both directions.
func TestManagerRoundTrip(t *testing.T) {
	type greetArgs struct {
		Name string `json:"name"`
	}
	upstream := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "1.0"}, nil)
	mcp.AddTool(upstream, &mcp.Tool{Name: "greet", Description: "says hi after asking"},
		func(ctx context.Context, req *mcp.CallToolRequest, a greetArgs) (*mcp.CallToolResult, any, error) {
			res, err := req.Session.Elicit(ctx, &mcp.ElicitParams{
				Message:         "Allow greeting?",
				RequestedSchema: map[string]any{"type": "object", "properties": map[string]any{"ok": map[string]any{"type": "boolean"}}},
			})
			if err != nil {
				return nil, nil, err
			}
			if res.Action != "accept" || res.Content["ok"] != true {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "declined"}}}, nil, nil
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "hi " + a.Name}}}, nil, nil
		})
	ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return upstream }, nil))
	defer ts.Close()

	m := NewManager("") // no file persistence in tests
	if err := m.Load(`{"mcpServers": {"fake": {"url": "` + ts.URL + `"}}}`); err != nil {
		t.Fatal(err)
	}
	s, ok := m.Get("fake")
	if !ok {
		t.Fatal("server not registered")
	}
	if err := s.Connect(); err != nil {
		t.Fatal(err)
	}
	defer s.Disconnect()
	if info := s.Info(); info == nil || info.ServerInfo.Name != "fake" {
		t.Fatalf("initialize result: %+v", info)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tools, err := s.Session().ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 1 || tools.Tools[0].Name != "greet" {
		t.Fatalf("tools: %v %v", tools, err)
	}

	type outcome struct {
		res *mcp.CallToolResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := s.Session().CallTool(ctx, &mcp.CallToolParams{Name: "greet", Arguments: map[string]any{"name": "bob"}})
		done <- outcome{res, err}
	}()

	var pending []*Elicitation
	for deadline := time.Now().Add(5 * time.Second); len(pending) == 0 && time.Now().Before(deadline); {
		pending = s.Pending()
		time.Sleep(10 * time.Millisecond)
	}
	if len(pending) != 1 || pending[0].Message != "Allow greeting?" || len(pending[0].Fields) != 1 {
		t.Fatalf("pending elicitations: %+v", pending)
	}
	if !s.Answer(pending[0].ID, &mcp.ElicitResult{Action: "accept", Content: map[string]any{"ok": true}}) {
		t.Fatal("answer: elicitation already gone")
	}
	out := <-done
	if out.err != nil || out.res.IsError || out.res.Content[0].(*mcp.TextContent).Text != "hi bob" {
		t.Fatalf("call result: %+v %v", out.res, out.err)
	}
	if len(s.Pending()) != 0 {
		t.Fatal("elicitation still pending after answer")
	}

	seen := map[string]bool{}
	for _, e := range s.Transcript.Since(0) {
		seen[e.Dir+" "+e.Method] = true
	}
	for _, want := range []string{"send initialize", "send notifications/initialized", "send tools/list", "send tools/call", "recv elicitation/create"} {
		if !seen[want] {
			t.Errorf("transcript missing %q; saw %v", want, seen)
		}
	}

	s.Disconnect()
	if s.Connected() || s.Session() != nil {
		t.Fatal("still connected after Disconnect")
	}
}

// TestHTTPClient_HeadersStayOnServerOrigin: a server's configured headers reach that server,
// follow a redirect within its origin, and are not sent to another host it redirects to.
func TestHTTPClient_HeadersStayOnServerOrigin(t *testing.T) {
	type seen struct{ auth, key string }
	record := func(into *atomic.Value, r *http.Request) {
		into.Store(seen{r.Header.Get("Authorization"), r.Header.Get("X-Api-Key")})
	}
	var otherHits atomic.Int32
	var atOther, atVendor, atVendorNew atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		record(&atOther, r)
	}))
	defer other.Close()
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			record(&atVendor, r)
			http.Redirect(w, r, other.URL+"/mcp", http.StatusTemporaryRedirect)
		case "/old":
			http.Redirect(w, r, "/new", http.StatusTemporaryRedirect)
		case "/new":
			record(&atVendorNew, r)
		}
	}))
	defer vendor.Close()

	client := httpClient(vendor.URL+"/mcp", map[string]string{"Authorization": "Bearer SERVER-SECRET", "X-Api-Key": "k-123"})
	want := seen{"Bearer SERVER-SECRET", "k-123"}
	for _, path := range []string{"/away", "/old"} {
		res, err := client.Post(vendor.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		res.Body.Close()
	}

	if got, _ := atVendor.Load().(seen); got != want {
		t.Errorf("the server did not receive its headers: got %+v", got)
	}
	if got, _ := atVendorNew.Load().(seen); got != want {
		t.Errorf("the headers were dropped on a redirect within the server's origin: got %+v", got)
	}
	if otherHits.Load() == 0 {
		t.Fatal("the redirect was not followed, so this test shows nothing about the other host")
	}
	if got, _ := atOther.Load().(seen); got != (seen{}) {
		t.Errorf("the server's headers were sent to the host it redirected to: %+v", got)
	}
}

func TestOriginOf(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"https://mcp.vendor.com/mcp", "https://mcp.vendor.com:443"},
		{"https://MCP.Vendor.com:443/x?y=1", "https://mcp.vendor.com:443"},
		{"http://localhost/mcp", "http://localhost:80"},
		{"http://127.0.0.1:8090/mcp", "http://127.0.0.1:8090"},
		{"http://[::1]:8090/mcp", "http://::1:8090"},
		{"https://evil.vendor.com/mcp", "https://evil.vendor.com:443"},
		{"http://mcp.vendor.com/mcp", "http://mcp.vendor.com:80"},
		{"ftp://vendor.com/mcp", ""},
		{"/just/a/path", ""},
		{"https:///mcp", ""},
		{"", ""},
	} {
		u, err := url.Parse(c.in)
		if err != nil {
			t.Fatalf("parse %q: %v", c.in, err)
		}
		if got := originOf(u); got != c.want {
			t.Errorf("originOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := originOf(nil); got != "" {
		t.Errorf("originOf(nil) = %q, want \"\"", got)
	}
}
