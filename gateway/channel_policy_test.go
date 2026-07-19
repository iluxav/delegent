package gateway

import (
	"context"
	"net/http/httptest"
	"reflect"
	"testing"

	"delegent.dev/gateway/agentkey"
	"delegent.dev/gateway/store"
)

// A key's ordered consent-channel policy overrides capability-order routing (and the env FF_*
// bypasses). The web console is ALWAYS the final fallback after the list — a policy picks the
// channel but can never remove human approval. Empty policy = auto (today's behavior).

func TestConsentModePolicy_ConsoleOnly(t *testing.T) {
	full := clientCaps{elicitation: true, uiExt: true}
	// the "my-local-harness" case: a fully-capable client forced straight to the console
	if got := full.consentMode(true, featureFlags{}, []string{"console"}); got != consentConsole {
		t.Fatalf("policy [console]: got %q, want console", got)
	}
}

func TestConsentModePolicy_OrderRespected(t *testing.T) {
	full := clientCaps{elicitation: true, uiExt: true}
	if got := full.consentMode(true, featureFlags{}, []string{"widget", "elicitation"}); got != consentWidget {
		t.Fatalf("policy [widget,elicitation]: got %q, want widget", got)
	}
	if got := full.consentMode(true, featureFlags{}, []string{"elicitation", "widget"}); got != consentInline {
		t.Fatalf("policy [elicitation,widget]: got %q, want inline", got)
	}
}

func TestConsentModePolicy_FallsBackToConsole(t *testing.T) {
	// the chatgpt case: policy wants elicitation but the client never declared it
	noElic := clientCaps{}
	if got := noElic.consentMode(true, featureFlags{}, []string{"elicitation"}); got != consentConsole {
		t.Fatalf("unsupportable policy: got %q, want console fallback", got)
	}
	// unknown channel names (e.g. a future "slack" on an old build) are skipped, not fatal
	if got := noElic.consentMode(true, featureFlags{}, []string{"slack"}); got != consentConsole {
		t.Fatalf("unknown channel: got %q, want console fallback", got)
	}
	// console disabled at the deployment level is the only way to fail closed
	if got := noElic.consentMode(false, featureFlags{}, []string{"elicitation"}); got != consentDenied {
		t.Fatalf("unsupportable policy + console off: got %q, want denied", got)
	}
}

func TestConsentModePolicy_OverridesEnvFlags(t *testing.T) {
	full := clientCaps{elicitation: true, uiExt: true}
	ff := featureFlags{bypassElicitation: true, bypassWidget: true}
	// an explicit key policy wins over the process-wide FF_* bypasses
	if got := full.consentMode(true, ff, []string{"elicitation"}); got != consentInline {
		t.Fatalf("policy vs ff: got %q, want inline", got)
	}
}

// makeVerifier must thread the key's policy into TokenInfo.Extra so the initialize handler can
// stash it per connection (channelPolicyFromContext reads the same field back).
func TestMakeVerifier_ThreadsConsentChannels(t *testing.T) {
	st := store.NewMemStore()
	ctx := context.Background()
	seedDisabledEntitlement(t, st) // reuses the gh target + usr_op entitlement fixture

	const token = "dgk_chan_token"
	if err := st.PutAgentKey(ctx, &store.AgentKey{
		ID: "akey_chan", UserID: "usr_op", Hash: agentkey.Hash(token), Prefix: "dgk_chan",
		ConsentChannels: []string{"console"},
	}); err != nil {
		t.Fatalf("put key: %v", err)
	}
	info, err := makeVerifier(st, "gh")(ctx, token, httptest.NewRequest("POST", "/mcp/gh", nil))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	got, _ := info.Extra["consent_channels"].([]string)
	if !reflect.DeepEqual(got, []string{"console"}) {
		t.Fatalf("Extra[consent_channels] = %v, want [console]", got)
	}
}

func TestConsentModePolicy_EmptyIsAuto(t *testing.T) {
	full := clientCaps{elicitation: true, uiExt: true}
	// no policy: capability order, and the env ff bypasses still apply
	if got := full.consentMode(true, featureFlags{}, nil); got != consentInline {
		t.Fatalf("auto: got %q, want inline", got)
	}
	if got := full.consentMode(true, featureFlags{bypassElicitation: true}, nil); got != consentWidget {
		t.Fatalf("auto + bypassElicitation: got %q, want widget", got)
	}
}
