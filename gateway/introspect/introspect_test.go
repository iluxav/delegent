package introspect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDraft_FakeVendorTools(t *testing.T) {
	cases := []struct {
		name        string
		wantEffect  string
		wantScope   string
		wantUnknown bool
	}{
		{"read_file", "read", "files:read", false},
		{"search_files", "read", "files:read", false},
		{"write_file", "write", "files:write", false},
		{"delete_file", "destructive", "files:write", false},
		{"send_email", "external", "mail:send", false},
		{"purchase", "spends", "billing:spend", false},
		{"exfiltrate_everything", "unknown", "", true}, // the lying tool -> fail closed
	}
	for _, c := range cases {
		d := draft(&mcp.Tool{Name: c.name})
		if d.Effect != c.wantEffect || d.Scope != c.wantScope || d.Unknown != c.wantUnknown {
			t.Errorf("%s: got effect=%q scope=%q unknown=%v; want effect=%q scope=%q unknown=%v",
				c.name, d.Effect, d.Scope, d.Unknown, c.wantEffect, c.wantScope, c.wantUnknown)
		}
	}
}

func TestDraft_LyingAnnotationStillClassifiedByName(t *testing.T) {
	// A server marks a destructive-sounding tool readOnly. Name wins — we don't trust the hint.
	ro := true
	d := draft(&mcp.Tool{Name: "delete_account", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: ro}})
	if d.Effect != "destructive" {
		t.Fatalf("name should override a lying readOnly hint, got %q", d.Effect)
	}
}

func TestDraft_UnknownFallsToAnnotationThenClosed(t *testing.T) {
	// No verb in the name: a readOnly hint drafts read; nothing drafts unknown.
	d := draft(&mcp.Tool{Name: "frobnicate", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}})
	if d.Effect != "read" {
		t.Fatalf("readOnly hint should draft read when no verb matches, got %q", d.Effect)
	}
	d2 := draft(&mcp.Tool{Name: "frobnicate"})
	if !d2.Unknown {
		t.Fatalf("no verb + no hint should be unknown, got %q", d2.Effect)
	}
}

// TestIntrospect_CredentialStaysOnEndpointOrigin: an endpoint that answers with a redirect to
// another host receives the credential; the host it redirects to does not.
func TestIntrospect_CredentialStaysOnEndpointOrigin(t *testing.T) {
	var otherHits atomic.Int32
	var otherAuth, vendorAuth atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		otherAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusBadRequest) // not an MCP server: Introspect fails after this
	}))
	defer other.Close()
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vendorAuth.Store(r.Header.Get("Authorization"))
		http.Redirect(w, r, other.URL+"/mcp", http.StatusTemporaryRedirect)
	}))
	defer vendor.Close()

	_, _ = Introspect(context.Background(), vendor.URL+"/mcp", "VENDOR-SECRET")

	if got, _ := vendorAuth.Load().(string); got != "Bearer VENDOR-SECRET" {
		t.Fatalf("the endpoint did not receive its credential: got %q", got)
	}
	if otherHits.Load() == 0 {
		t.Fatal("the redirect was not followed, so this test shows nothing about the other host")
	}
	if got, _ := otherAuth.Load().(string); got != "" {
		t.Fatalf("the credential was sent to the host the endpoint redirected to: %q", got)
	}
}
