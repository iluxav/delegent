package introspect

import (
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
