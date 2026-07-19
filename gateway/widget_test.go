package gateway

import (
	"strings"
	"testing"

	core "delegent.dev/protocol"
)

// TestWidgetPayload_CarriesHeadline: when a guarded call stashed its callMeta on the connection,
// the widget payload leads with the SAME legible headline the elicitation dialog shows — action,
// target, risk, and the declared intent — and also persists it on the pending record (so the
// bridged resource-read path renders it too). With NO stashed meta the payload carries no
// headline and the widget falls back to the reason line.
func TestWidgetPayload_CarriesHeadline(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)

	const connID = "conn-widget"
	scopes := []string{"files:read"}
	reason := "tool: get_file_contents"
	cr := g.cp.DescribeConsent("root:alice", scopes, reason)
	pc := g.pending.findOrCreate("root:alice", connID, scopes, reason)

	meta := callMeta{
		Tool:     "get_file_contents",
		ToolDesc: "Read file contents",
		Target:   "github",
		Intent:   "reading a config file",
		Effect:   core.EffectRead,
	}
	g.setConnMeta(connID, meta)

	payload := g.buildWidgetPayload(connID, pc, cr)

	headline, ok := payload["headline"].(string)
	if !ok || headline == "" {
		t.Fatalf("payload missing headline; got %#v", payload["headline"])
	}
	for _, want := range []string{
		"Read file contents",        // the action (tool description)
		"github",                    // the target
		riskPhrase(core.EffectRead), // "read-only" risk phrase
		"reading a config file",     // the declared intent, on the Why line
	} {
		if !strings.Contains(headline, want) {
			t.Errorf("headline missing %q\ngot: %q", want, headline)
		}
	}
	if payload["intent"] != meta.Intent {
		t.Errorf("payload intent = %v, want %q", payload["intent"], meta.Intent)
	}

	// The headline must also be persisted on the record for serveConsentToken's resource-read.
	if rec, found := g.pending.latestForConn(connID); !found {
		t.Fatalf("pending record for %s vanished", connID)
	} else if rec.Headline != headline || rec.Intent != meta.Intent {
		t.Errorf("record display not persisted: headline=%q intent=%q", rec.Headline, rec.Intent)
	}

	// No stashed meta (a direct request_access): no headline — the widget uses the reason line.
	const bareConn = "conn-nometa"
	barePC := g.pending.findOrCreate("root:alice", bareConn, scopes, "request_access")
	bareCR := g.cp.DescribeConsent("root:alice", scopes, "request_access")
	barePayload := g.buildWidgetPayload(bareConn, barePC, bareCR)
	if _, present := barePayload["headline"]; present {
		t.Errorf("payload with no stashed meta must omit headline; got %#v", barePayload["headline"])
	}
	if _, present := barePayload["intent"]; present {
		t.Errorf("payload with no stashed meta must omit intent; got %#v", barePayload["intent"])
	}
}
