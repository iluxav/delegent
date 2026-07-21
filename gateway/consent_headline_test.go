package gateway

import (
	"strings"
	"testing"

	"delegent.dev/gateway/introspect"
	core "delegent.dev/protocol"
)

// TestConsentHeadline_ActionRiskIntent: the shared headline leads with the tool's human action,
// the target, the effect-as-risk phrase, and (when declared) the intent — and omits the "Why"
// line entirely when no intent was declared, degrading to action + risk.
func TestConsentHeadline_ActionRiskIntent(t *testing.T) {
	m := callMeta{
		Tool:     "list_repos",
		ToolDesc: "List your repositories",
		Target:   "github",
		Intent:   "finding old repos to archive",
		Effect:   core.EffectRead,
	}
	got := consentHeadline("main-agent-x", m)

	for _, want := range []string{
		"main-agent-x",
		"List your repositories",
		"github",
		riskPhrase(core.EffectRead), // "read-only"
		"finding old repos to archive",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("headline missing %q\ngot: %q", want, got)
		}
	}
	if !strings.Contains(got, "Why:") {
		t.Errorf("headline with an intent must carry a Why line\ngot: %q", got)
	}

	// No declared intent: the Why line is dropped, but action + risk still lead.
	m.Intent = ""
	got = consentHeadline("main-agent-x", m)
	if strings.Contains(got, "Why:") {
		t.Errorf("headline with no intent must omit the Why line\ngot: %q", got)
	}
	for _, want := range []string{"List your repositories", riskPhrase(core.EffectRead)} {
		if !strings.Contains(got, want) {
			t.Errorf("intent-less headline missing %q\ngot: %q", want, got)
		}
	}

	// No description falls back to a humanized tool name.
	got = consentHeadline("main-agent-x", callMeta{Tool: "list_repos", Target: "github", Effect: core.EffectRead})
	if !strings.Contains(got, "list repos") {
		t.Errorf("headline should humanize the tool name when no description\ngot: %q", got)
	}
}

// TestConsentHeadline_Semantics: the display-only semantic markers append to the risk clause — an
// irreversible reversibility adds "⚠️ irreversible", an affirmative open-world adds the
// external-service marker, reversible-then-openworld in order, and all-unknown/empty Semantics add
// NEITHER marker (no stray "·" clause). The Why line still renders after the risk line.
func TestConsentHeadline_Semantics(t *testing.T) {
	dest := core.EffectDestructive

	// Irreversible marker.
	got := consentHeadline("main-agent-x", callMeta{
		Tool:      "delete_repo",
		ToolDesc:  "Delete a repository",
		Target:    "github",
		Effect:    dest,
		Semantics: introspect.ToolSemantics{Reversible: "irreversible"},
	})
	if !strings.Contains(got, "irreversible") {
		t.Errorf("irreversible headline missing marker\ngot: %q", got)
	}

	// Open-world marker.
	got = consentHeadline("main-agent-x", callMeta{
		Tool:      "web_fetch",
		ToolDesc:  "Fetch a URL",
		Target:    "web",
		Effect:    core.EffectRead,
		Semantics: introspect.ToolSemantics{OpenWorld: "yes"},
	})
	if !strings.Contains(got, "external service") {
		t.Errorf("open-world headline missing marker\ngot: %q", got)
	}

	// Both markers, reversible-then-openworld order, and Why line still last.
	got = consentHeadline("main-agent-x", callMeta{
		Tool:      "delete_repo",
		ToolDesc:  "Delete a repository",
		Target:    "github",
		Intent:    "cleaning up",
		Effect:    dest,
		Semantics: introspect.ToolSemantics{Reversible: "irreversible", OpenWorld: "yes"},
	})
	iRev := strings.Index(got, "irreversible")
	iExt := strings.Index(got, "external service")
	iWhy := strings.Index(got, "Why:")
	if iRev < 0 || iExt < 0 || iWhy < 0 {
		t.Fatalf("expected all markers + Why line\ngot: %q", got)
	}
	if !(iRev < iExt && iExt < iWhy) {
		t.Errorf("expected order irreversible < external service < Why\ngot: %q", got)
	}

	// All-unknown/empty Semantics adds NEITHER marker and no stray "·" clause.
	got = consentHeadline("main-agent-x", callMeta{
		Tool:      "delete_repo",
		ToolDesc:  "Delete a repository",
		Target:    "github",
		Effect:    dest,
		Semantics: introspect.ToolSemantics{Reversible: "unknown", OpenWorld: "unknown", Idempotent: "unknown", Cost: "unknown"},
	})
	if strings.Contains(got, "irreversible") || strings.Contains(got, "external service") || strings.Contains(got, "·") {
		t.Errorf("unknown Semantics must add no marker or stray '·'\ngot: %q", got)
	}
}

// TestRiskPhrase: every effect maps to its operator-facing phrase, the strongest effect wins for a
// combined bitmask, and an empty/unknown mask degrades to a neutral "changes state".
func TestRiskPhrase(t *testing.T) {
	cases := []struct {
		name string
		eff  core.Effect
		want string
	}{
		{"read", core.EffectRead, "read-only"},
		{"write", core.EffectWrite, "✍️ writes data"},
		{"destructive", core.EffectDestructive, "⚠️ destructive — can delete or overwrite"},
		{"spend", core.EffectSpends, "💸 spends money"},
		{"empty", 0, "changes state"},
		// strongest-effect-wins: read+write → write; read+destructive → destructive.
		{"read+write", core.EffectRead | core.EffectWrite, "✍️ writes data"},
		{"read+destructive", core.EffectRead | core.EffectDestructive, "⚠️ destructive — can delete or overwrite"},
		{"write+spend", core.EffectWrite | core.EffectSpends, "💸 spends money"},
	}
	for _, tc := range cases {
		if got := riskPhrase(tc.eff); got != tc.want {
			t.Errorf("%s: riskPhrase(%d) = %q, want %q", tc.name, tc.eff, got, tc.want)
		}
	}
}
