package gateway

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestLooksTransient: every listed 5xx/upstream/transient signal trips true; a genuine 4xx
// auth/validation error stays false so the agent acts on it rather than narrating an outage.
func TestLooksTransient(t *testing.T) {
	trueCases := []string{
		"503 Service Unavailable",
		"HTTP 502 Bad Gateway",
		"got a 500 from the vendor",
		"504 gateway timeout",
		"429 Too Many Requests",
		"the service is temporarily unavailable",
		"rate limit exceeded",
		"upstream connection reset",
		"Bad Gateway",
		"gateway timeout after 30s",
		"please try again later",
		"Rate Limit", // case-insensitive
	}
	for _, s := range trueCases {
		if !looksTransient(s) {
			t.Errorf("looksTransient(%q) = false, want true", s)
		}
	}
	falseCases := []string{
		"404 not found",
		"invalid argument",
		"401 unauthorized",
		"403 forbidden",
		"missing required field 'path'",
		"",
	}
	for _, s := range falseCases {
		if looksTransient(s) {
			t.Errorf("looksTransient(%q) = true, want false", s)
		}
	}
}

func errResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// TestAnnotateTransient: a transient IsError result gets the Delegent note APPENDED (vendor content
// preserved); a non-transient error and a non-error result pass through untouched.
func TestAnnotateTransient(t *testing.T) {
	// Transient: note appended, original content kept.
	res := annotateTransient(errResult("vendor returned 503 service unavailable"))
	if len(res.Content) != 2 {
		t.Fatalf("transient result should have 2 content blocks (vendor + note), got %d", len(res.Content))
	}
	if !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "503") {
		t.Errorf("vendor content must be preserved as the first block, got %q", res.Content[0].(*mcp.TextContent).Text)
	}
	if !strings.Contains(res.Content[1].(*mcp.TextContent).Text, "Delegent") {
		t.Errorf("second block must be the Delegent note, got %q", res.Content[1].(*mcp.TextContent).Text)
	}

	// Non-transient (404): passes through with no added note.
	res404 := annotateTransient(errResult("404 not found"))
	if len(res404.Content) != 1 {
		t.Errorf("a 404 must NOT be annotated, got %d content blocks", len(res404.Content))
	}

	// Non-error result: untouched even if the text mentions a signal.
	ok := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "500 items processed"}}}
	if got := annotateTransient(ok); len(got.Content) != 1 {
		t.Errorf("a non-error result must never be annotated, got %d content blocks", len(got.Content))
	}

	// Nil is safe.
	if annotateTransient(nil) != nil {
		t.Error("annotateTransient(nil) must return nil")
	}
}

// TestReqAccessWidgetRedirect: request_access bounces a widget-mode client to open_access_dialog,
// and leaves inline/console clients to proceed (nil redirect).
func TestReqAccessWidgetRedirect(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	g.consoleConsent = true

	g.setCaps("widgetConn", clientCaps{uiExt: true})
	r := g.reqAccessWidgetRedirect("widgetConn")
	if r == nil {
		t.Fatal("a widget-mode client must be redirected from request_access")
	}
	if !strings.Contains(resultText(r), "open_access_dialog") {
		t.Errorf("redirect must name open_access_dialog, got %q", resultText(r))
	}
	if r.IsError {
		t.Error("the redirect must be a NON-error result")
	}

	// Inline (elicitation) client: no redirect — request_access is its batch tool.
	g.setCaps("inlineConn", clientCaps{elicitation: true})
	if g.reqAccessWidgetRedirect("inlineConn") != nil {
		t.Error("an inline client must NOT be redirected from request_access")
	}
	// Console client: no redirect (request_access parks on the console).
	g.setCaps("consoleConn", clientCaps{})
	if g.reqAccessWidgetRedirect("consoleConn") != nil {
		t.Error("a console client must NOT be redirected from request_access")
	}
}

// TestOpenDialogNonWidgetRedirect: open_access_dialog bounces a NON-widget client back to
// request_access, and lets a widget client through (nil redirect → proceed to the widget flow).
func TestOpenDialogNonWidgetRedirect(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	g.consoleConsent = true

	// Inline client mistakenly calling open_access_dialog: bounced to request_access.
	g.setCaps("inlineConn", clientCaps{elicitation: true})
	r := g.openDialogNonWidgetRedirect("inlineConn")
	if r == nil {
		t.Fatal("a non-widget client must be redirected from open_access_dialog")
	}
	if !strings.Contains(resultText(r), "request_access") {
		t.Errorf("redirect must name request_access, got %q", resultText(r))
	}
	if r.IsError {
		t.Error("the redirect must be a NON-error result")
	}

	// Console client (neither elicitation nor widget): also bounced.
	g.setCaps("consoleConn", clientCaps{})
	if g.openDialogNonWidgetRedirect("consoleConn") == nil {
		t.Error("a console client must be redirected from open_access_dialog")
	}

	// Widget client: no redirect — it proceeds into the widget flow.
	g.setCaps("widgetConn", clientCaps{uiExt: true})
	if g.openDialogNonWidgetRedirect("widgetConn") != nil {
		t.Error("a widget client must NOT be redirected from open_access_dialog")
	}
}
