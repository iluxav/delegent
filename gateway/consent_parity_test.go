package gateway

import (
	"context"
	"strings"
	"testing"

	"delegent.dev/gateway/introspect"
	core "delegent.dev/protocol"
)

// Parity: the console park path must persist the SAME legible display the elicitation/widget
// dialogs render — headline (action + risk markers) and the agent's declared intent — so the
// approvals card and out-of-band notices never say less than the in-chat dialog would.
func TestConsoleParkPersistsHeadlineAndIntent(t *testing.T) {
	r, g := consoleRegistry(t)

	meta := callMeta{
		Tool: "write_file", ToolDesc: "write a file", Target: g.targetID,
		Effect: core.EffectWrite, Intent: "save the meeting notes",
		Semantics: introspect.ToolSemantics{Reversible: "irreversible"},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.consoleConsentBlock(context.Background(), "conn1", "write_file", []string{"files:write"}, meta)
	}()

	pv := waitForPending(t, r, "root:alice")

	// the live console view carries the display fields
	if !strings.Contains(pv.Headline, "write a file") || !strings.Contains(pv.Headline, "irreversible") {
		t.Fatalf("PendingView.Headline = %q — want action + risk marker", pv.Headline)
	}
	if pv.Intent != "save the meeting notes" {
		t.Fatalf("PendingView.Intent = %q", pv.Intent)
	}

	// and so does the DURABLE row (what telegram + the approvals history read)
	row, err := g.st.GetConsentRequest(context.Background(), pv.ID)
	if err != nil {
		t.Fatalf("durable row: %v", err)
	}
	if !strings.Contains(row.Headline, "write a file") || !strings.Contains(row.Headline, "irreversible") {
		t.Fatalf("row.Headline = %q — want action + risk marker", row.Headline)
	}
	if row.Intent != "save the meeting notes" {
		t.Fatalf("row.Intent = %q", row.Intent)
	}

	// unblock the parked call so the goroutine exits cleanly
	if ok, err := r.ResolveConsent(pv.Principal, pv.ID, nil, 0, 0); err != nil || !ok {
		t.Fatalf("cleanup resolve: ok=%v err=%v", ok, err)
	}
	<-done
}
