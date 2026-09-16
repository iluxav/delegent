package main

import (
	"strings"
	"testing"
)

func TestParseConfig(t *testing.T) {
	specs, err := ParseConfig([]byte(`{"mcpServers": {
		"local":  {"command": "npx", "args": ["-y", "some-server"], "env": {"A": "1"}, "cwd": "/tmp"},
		"remote": {"url": "https://example.com/mcp", "headers": {"Authorization": "Bearer t"}},
		"legacy": {"type": "sse", "url": "https://example.com/sse"},
		"cursor": {"type": "streamableHttp", "url": "https://example.com/mcp"}
	}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(specs))
	for i, s := range specs {
		got[i] = s.Name + ":" + s.Kind()
	}
	want := "cursor:http legacy:sse local:stdio remote:http"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %q, want %q", strings.Join(got, " "), want)
	}
	if specs[2].Summary() != "npx -y some-server" || specs[3].Summary() != "https://example.com/mcp" {
		t.Fatalf("summaries: %q / %q", specs[2].Summary(), specs[3].Summary())
	}

	// a bare map (one server pasted without the wrapper) is accepted too
	if specs, err = ParseConfig([]byte(`{"only": {"url": "https://x/mcp"}}`)); err != nil || len(specs) != 1 || specs[0].Name != "only" {
		t.Fatalf("bare map: %v %v", specs, err)
	}

	// round trip through the saved form
	specs, err = ParseConfig(MarshalConfig(specs))
	if err != nil || len(specs) != 1 || specs[0].URL != "https://x/mcp" {
		t.Fatalf("round trip: %v %v", specs, err)
	}

	for name, bad := range map[string]string{
		"not json":         `{`,
		"stdio no command": `{"mcpServers": {"a": {"args": ["x"]}}}`,
		"http no url":      `{"mcpServers": {"a": {"type": "http"}}}`,
		"wrong shape":      `{"mcpServers": "nope"}`,
		"empty":            `{}`,
	} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestStandaloneSSEDefaults(t *testing.T) {
	specs, err := ParseConfig([]byte(`{"mcpServers": {
		"fast": {"url": "https://x/mcp"},
		"watch": {"url": "https://y/mcp", "standaloneSSE": true}
	}}`))
	if err != nil {
		t.Fatal(err)
	}
	// fast defaults off; watch opts in
	if specs[0].StandaloneSSE || !specs[1].StandaloneSSE {
		t.Fatalf("standaloneSSE: fast=%v watch=%v", specs[0].StandaloneSSE, specs[1].StandaloneSSE)
	}
	// the opt-in survives a save/reload round trip
	specs, _ = ParseConfig(MarshalConfig(specs))
	if specs[0].StandaloneSSE || !specs[1].StandaloneSSE {
		t.Fatalf("round trip lost standaloneSSE: %v %v", specs[0].StandaloneSSE, specs[1].StandaloneSSE)
	}
}
