package dclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A handed-back task is polled to completion inside Call, so the caller sees only the answer.
func TestCallAwaitsHandedBackTasks(t *testing.T) {
	var polls atomic.Int32
	srv := mcp.NewServer(&mcp.Implementation{Name: "fake-delegent", Version: "0"}, nil)
	open := map[string]any{"type": "object", "additionalProperties": true}
	text := func(s string) *mcp.CallToolResult {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
	}
	srv.AddTool(&mcp.Tool{Name: "slow__think", Description: "slow", InputSchema: open}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return text("thinking\n\n[agent task task-slow-1 is still working — check later with get_task {task_id: \"task-slow-1\"}]"), nil
	})
	srv.AddTool(&mcp.Tool{Name: "slow__get_task", Description: "status", InputSchema: open}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			TaskID string `json:"task_id"`
		}
		_ = json.Unmarshal(req.Params.Arguments, &a)
		if a.TaskID != "task-slow-1" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "unknown task"}}}, nil
		}
		if polls.Add(1) < 2 {
			return text("[agent task task-slow-1 is still working — check later with get_task {task_id: \"task-slow-1\"}]"), nil
		}
		return text("the answer"), nil
	})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	ts := httptest.NewServer(h)
	defer ts.Close()

	c := &Client{Endpoint: ts.URL, Key: "dgk_test"}
	s, err := c.Open(context.Background(), "sess_x")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var statuses []string
	out, err := s.Call(context.Background(), "slow__think", map[string]any{}, "why", func(line string) { statuses = append(statuses, line) })
	if err != nil {
		t.Fatal(err)
	}
	if out != "the answer" {
		t.Errorf("Call returned %q, want the finished answer", out)
	}
	if polls.Load() != 2 {
		t.Errorf("polled %d times, want 2", polls.Load())
	}
	if len(statuses) == 0 || !strings.Contains(statuses[0], "waiting for slow") {
		t.Errorf("no waiting status reported: %v", statuses)
	}
}
