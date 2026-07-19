package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway/agentkey"
	"delegent.dev/gateway/id"
	"delegent.dev/gateway/store"
)

// TestStdioRoundTrip drives a REAL MCP session through the built binary: a fake upstream MCP
// vendor is stood up over HTTP, the instance is initialized and the target provisioned via
// the CLI code paths, and then an MCP client launches `delegent-gateway stdio` exactly like
// Claude Desktop would — asserting the aggregate surface (namespaced tools) comes back and a
// consent-gated call flows through elicitation to the vendor and back.
func TestStdioRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary; skipped in -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// no ambient config may leak into the instance under test
	t.Setenv("DELEGENT_MASTER_KEY", "")
	t.Setenv("DELEGENT_AUTH", "")
	t.Setenv("DELEGENT_AGENT_KEY", "")

	// 1. the fake upstream vendor: one echo tool over streamable HTTP
	type echoArgs struct {
		Text string `json:"text"`
	}
	upstream := mcp.NewServer(&mcp.Implementation{Name: "fake-vendor", Version: "1.0.0"}, nil)
	mcp.AddTool(upstream, &mcp.Tool{Name: "read_file", Description: "Read back the given text."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a echoArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo:" + a.Text}}}, nil, nil
		})
	ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return upstream }, nil))
	defer ts.Close()

	// 2. init the instance + provision the target through the CLI paths
	home := t.TempDir()
	if err := cmdInit([]string{"--home", home}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := targetAdd([]string{"--home", home, "--id", "fake", "--endpoint", ts.URL}); err != nil {
		t.Fatalf("target add: %v", err)
	}

	// 3. mint an agent key straight into the store (keyMint prints the plaintext; here we need it)
	e, err := requireOperator(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	full, hash, prefix := agentkey.New()
	if err := e.st.PutAgentKey(ctx, &store.AgentKey{
		ID: id.New("akey"), UserID: e.operator, Hash: hash, Prefix: prefix, Name: "test", CreatedAt: nowMillis(),
	}); err != nil {
		t.Fatal(err)
	}

	// 4. build the binary and connect over stdio, approving every consent ask via elicitation
	bin := filepath.Join(t.TempDir(), "delegent-gateway")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "round-trip-test", Version: "0"}, &mcp.ClientOptions{
		ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			content := map[string]any{}
			if schema, ok := req.Params.RequestedSchema.(map[string]any); ok {
				if props, ok := schema["properties"].(map[string]any); ok {
					for name := range props {
						if strings.HasPrefix(name, "s") && name != "ttl" {
							content[name] = "GRANT"
						}
					}
				}
			}
			return &mcp.ElicitResult{Action: "accept", Content: content}, nil
		},
	})
	session, err := client.Connect(ctx, &mcp.CommandTransport{
		Command: exec.Command(bin, "stdio", "--home", home, "--key", full),
	}, nil)
	if err != nil {
		t.Fatalf("connect over stdio: %v", err)
	}
	defer session.Close()

	// the aggregate surface: the vendor tool arrives namespaced <target>__<tool>
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	names := make([]string, 0, len(tools.Tools))
	found := false
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
		if tl.Name == "fake__read_file" {
			found = true
		}
	}
	if !found {
		t.Fatalf("aggregate did not expose fake__read_file; got %v", names)
	}

	// a consent-gated call: elicitation auto-grants, the call reaches the vendor and echoes back
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "fake__read_file",
		Arguments: map[string]any{
			"text":             "hello",
			"_delegent_intent": "round-trip test call",
		},
	})
	if err != nil {
		t.Fatalf("tools/call fake__read_file: %v", err)
	}
	var texts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			texts = append(texts, tc.Text)
		}
	}
	joined := strings.Join(texts, " | ")
	if res.IsError {
		t.Fatalf("call returned an error result: %s", joined)
	}
	if !strings.Contains(joined, "echo:hello") {
		t.Fatalf("vendor result did not round-trip; got %q", joined)
	}
}
