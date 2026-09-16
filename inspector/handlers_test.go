package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPagesRender executes every page-level template through the real mux so a template
// error surfaces here rather than in the browser.
func TestPagesRender(t *testing.T) {
	m := NewManager("")
	if err := m.Load(`{"mcpServers": {"local": {"command": "true"}, "remote": {"url": "https://example.com/mcp"}}}`); err != nil {
		t.Fatal(err)
	}
	a, err := newApp(m)
	if err != nil {
		t.Fatal(err)
	}
	h := a.routes()

	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code, rec.Body.String()
	}
	if code, body := get("/"); code != 200 || !strings.Contains(body, "MCP Inspector") || !strings.Contains(body, "remote") {
		t.Fatalf("index: %d %s", code, body)
	}
	if code, body := get("/?s=local"); code != 200 || !strings.Contains(body, "Connect") || !strings.Contains(body, "bg-accent-soft") {
		t.Fatalf("selected workspace: %d", code)
	}
	if code, _ := get("/servers/local"); code != 200 {
		t.Fatalf("workspace partial: %d", code)
	}
	if code, _ := get("/servers/local/info"); code != 200 {
		t.Fatalf("info: %d", code)
	}
	if code, _ := get("/servers/local/transcript?after=0"); code != 204 {
		t.Fatalf("empty transcript should be 204, got %d", code)
	}
	if code, _ := get("/servers/local/elicitations"); code != 204 {
		t.Fatalf("no elicitations should be 204, got %d", code)
	}
	if code, _ := get("/servers/nope"); code != 404 {
		t.Fatalf("unknown server: %d", code)
	}
	if code, body := get("/servers/local/tools"); code != 200 || !strings.Contains(body, "Not connected") {
		t.Fatalf("tools while disconnected: %d %s", code, body)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/servers", strings.NewReader("config=%7B"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "not valid JSON") {
		t.Fatalf("bad config: %d %s", rec.Code, rec.Body.String())
	}
}
