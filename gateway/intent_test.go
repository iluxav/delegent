package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"delegent.dev/gateway/store"
)

// TestIntent_InjectedIntoVendorSchema: withIntentField adds a _delegent_intent string property
// to a vendor tool's input schema without marking it required, and a nil schema becomes a minimal
// object schema carrying just that property. Delegent's own tools never go through this helper.
func TestIntent_InjectedIntoVendorSchema(t *testing.T) {
	// A vendor tool with an existing object schema.
	vendor := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{"type": "string"},
		},
		"required": []any{"path"},
	}
	out, ok := withIntentField(vendor).(map[string]any)
	if !ok {
		t.Fatalf("withIntentField returned %T, want map[string]any", withIntentField(vendor))
	}
	props, _ := out["properties"].(map[string]any)
	prop, ok := props["_delegent_intent"].(map[string]any)
	if !ok {
		t.Fatalf("_delegent_intent property missing: %#v", props)
	}
	if prop["type"] != "string" {
		t.Errorf("_delegent_intent type = %v, want string", prop["type"])
	}
	if prop["description"] == "" || prop["description"] == nil {
		t.Errorf("_delegent_intent must carry a description")
	}
	// Fail-soft: never required.
	if req, ok := out["required"].([]any); ok {
		for _, r := range req {
			if r == "_delegent_intent" {
				t.Errorf("_delegent_intent must NOT be in required")
			}
		}
	}
	// Original vendor schema must not be mutated (no leak upstream).
	if origProps, _ := vendor["properties"].(map[string]any); origProps["_delegent_intent"] != nil {
		t.Errorf("withIntentField mutated the source schema")
	}

	// A nil schema yields a minimal object schema with only the intent property.
	minOut, ok := withIntentField(nil).(map[string]any)
	if !ok {
		t.Fatalf("withIntentField(nil) returned %T, want map[string]any", withIntentField(nil))
	}
	if minOut["type"] != "object" {
		t.Errorf("nil schema type = %v, want object", minOut["type"])
	}
	if mp, _ := minOut["properties"].(map[string]any); mp["_delegent_intent"] == nil {
		t.Errorf("nil schema missing _delegent_intent property")
	}
}

// TestIntent_StrippedBeforeForward: stripIntent extracts the declared intent and removes the key
// from the arguments forwarded upstream, so the vendor never sees it. Absent intent degrades to "".
func TestIntent_StrippedBeforeForward(t *testing.T) {
	args := map[string]any{
		"path":             "/etc/hosts",
		"_delegent_intent": "read the hosts file to diagnose DNS",
	}
	intent, clean := stripIntent(args)
	if intent != "read the hosts file to diagnose DNS" {
		t.Errorf("intent = %q, want the declared string", intent)
	}
	if _, ok := clean["_delegent_intent"]; ok {
		t.Errorf("_delegent_intent must be stripped from forwarded args: %#v", clean)
	}
	if clean["path"] != "/etc/hosts" {
		t.Errorf("stripIntent dropped a real argument: %#v", clean)
	}

	// No intent present: empty string, args untouched.
	intent2, clean2 := stripIntent(map[string]any{"q": "x"})
	if intent2 != "" {
		t.Errorf("missing intent should yield \"\", got %q", intent2)
	}
	if clean2["q"] != "x" {
		t.Errorf("stripIntent altered args with no intent: %#v", clean2)
	}

	// Nil args must not panic.
	if intent3, clean3 := stripIntent(nil); intent3 != "" || clean3 != nil {
		t.Errorf("stripIntent(nil) = (%q, %#v), want (\"\", nil)", intent3, clean3)
	}
}

// TestIntent_RecordedOnEvent: the tool_call activity event carries the declared intent. The event
// is built + emitted at the top of the forward path — BEFORE the authorize/consent branch — so it
// fires on EVERY vendor call, including one whose scope was already held (no prompt shown).
func TestIntent_RecordedOnEvent(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	ctx := ctxWithToken(t, &auth.TokenInfo{
		UserID: "root:alice", Expiration: time.Now().Add(time.Hour),
		Extra: map[string]any{"key_prefix": "dgk_abc", "key_name": "ci-bot"},
	})

	const intent = "user asked me to read the release notes"
	g.emit(g.toolCallEvent(ctx, "", "read_file", intent, nil))

	got := waitForEvents(t, g.st, store.EventFilter{Type: store.EventToolCall}, 1)[0]
	if got.Type != store.EventToolCall || got.Tool != "read_file" {
		t.Fatalf("wrong event emitted: %+v", got)
	}
	if got.Intent != intent {
		t.Fatalf("tool_call event intent = %q, want %q", got.Intent, intent)
	}
}

// capIntent bounds an over-long intent to the payload cap so a giant _delegent_intent can never
// blow up the log; an empty intent stays empty (fail-soft — never an error, never a placeholder).
func TestIntent_CappedAndFailSoft(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	g.payloadMax = 16

	if got := g.capIntent(""); got != "" {
		t.Errorf("empty intent must stay empty, got %q", got)
	}
	long := strings.Repeat("x", 100)
	if got := g.capIntent(long); len(got) != 16 {
		t.Errorf("over-long intent must be capped to payloadMax (16), got len %d", len(got))
	}
	if got := g.capIntent("short"); got != "short" {
		t.Errorf("within-cap intent must pass through, got %q", got)
	}
}
