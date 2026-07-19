package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func newTestStore(now *int64) *pendingStore {
	n := 0
	return newPendingStore(
		func() int64 { return *now },
		func() string { n++; return "req_" + strings.Repeat("0", 15) + string(rune('a'+n)) },
	)
}

func TestPendingConsumeIsSingleUse(t *testing.T) {
	now := int64(1000)
	p := newTestStore(&now)
	pc := p.findOrCreate("root:alice", "conn1", []string{"files:read"}, "tool: read_file")
	if pc.WidgetToken == "" || pc.WidgetToken == pc.ID {
		t.Fatalf("record must carry a widget token distinct from its id: %+v", pc)
	}

	got, err := p.consume(pc.ID, pc.WidgetToken, "conn1", "root:alice")
	if err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if got.Principal != "root:alice" || got.ConnID != "conn1" || len(got.Scopes) != 1 || got.Scopes[0] != "files:read" {
		t.Fatalf("consumed record does not match what was created: %+v", got)
	}

	if _, err := p.consume(pc.ID, pc.WidgetToken, "conn1", "root:alice"); err == nil {
		t.Fatal("replayed consume of the same request_id must be rejected")
	} else if !strings.Contains(err.Error(), "already used") {
		t.Fatalf("replay error should say 'already used', got: %v", err)
	}
}

func TestPendingConsumeUnknown(t *testing.T) {
	now := int64(1000)
	p := newTestStore(&now)
	if _, err := p.consume("req_never_issued", "", "", ""); err == nil {
		t.Fatal("an id this gateway never issued must be rejected")
	} else if !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown-id error should say 'unknown', got: %v", err)
	}
}

func TestPendingConsumeExpired(t *testing.T) {
	now := int64(1000)
	p := newTestStore(&now)
	pc := p.findOrCreate("root:alice", "conn1", []string{"files:read"}, "r")

	now = 1000 + pendingTTL.Milliseconds() + 1
	if _, err := p.consume(pc.ID, pc.WidgetToken, "conn1", "root:alice"); err == nil {
		t.Fatal("an expired request_id must be rejected")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expiry error should say 'expired', got: %v", err)
	}
	// And it stays dead: the expired record was deleted, so a retry reads as unknown.
	if _, err := p.consume(pc.ID, pc.WidgetToken, "conn1", "root:alice"); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("a consumed-by-expiry id should now be unknown, got: %v", err)
	}
}

func TestPendingConsumeBindingMismatchesRejected(t *testing.T) {
	now := int64(1000)
	p := newTestStore(&now)
	pc := p.findOrCreate("root:alice", "conn1", []string{"files:read"}, "r")

	cases := []struct{ name, token, conn, principal string }{
		{"missing widget_token", "", "conn1", "root:alice"},
		{"wrong widget_token", "not-the-token", "conn1", "root:alice"},
		{"wrong connection", pc.WidgetToken, "conn2", "root:alice"},
		{"wrong principal", pc.WidgetToken, "conn1", "root:mallory"},
	}
	for _, c := range cases {
		if _, err := p.consume(pc.ID, c.token, c.conn, c.principal); err == nil {
			t.Fatalf("%s must be rejected", c.name)
		} else if !errors.Is(err, errConsentBinding) {
			t.Fatalf("%s should be a binding mismatch (uniform outward message), got: %v", c.name, err)
		}
	}
	// Forgery attempts must NOT burn the nonce: the real widget can still redeem it.
	if _, err := p.consume(pc.ID, pc.WidgetToken, "conn1", "root:alice"); err != nil {
		t.Fatalf("legitimate redemption after mismatched attempts failed: %v", err)
	}
}

func TestPendingFindOrCreateReusesLiveRecord(t *testing.T) {
	now := int64(1000)
	p := newTestStore(&now)
	a := p.findOrCreate("root:alice", "conn1", []string{"files:read", "files:write"}, "tool: write_file")
	b := p.findOrCreate("root:alice", "conn1", []string{"files:write", "files:read"}, "request_access")
	if a.ID != b.ID {
		t.Fatalf("same principal+conn+scope-set should reuse ONE nonce: %s vs %s", a.ID, b.ID)
	}
	// A different connection, principal, or scope set gets its own nonce.
	if c := p.findOrCreate("root:alice", "conn2", []string{"files:read", "files:write"}, "r"); c.ID == a.ID {
		t.Fatal("a different connection must not share a nonce")
	}
	if c := p.findOrCreate("root:bob", "conn1", []string{"files:read", "files:write"}, "r"); c.ID == a.ID {
		t.Fatal("a different principal must not share a nonce")
	}
	if c := p.findOrCreate("root:alice", "conn1", []string{"files:read"}, "r"); c.ID == a.ID {
		t.Fatal("a different scope set must not share a nonce")
	}
	// Once consumed, the same ask mints a FRESH nonce.
	if _, err := p.consume(a.ID, a.WidgetToken, "conn1", "root:alice"); err != nil {
		t.Fatalf("consume failed: %v", err)
	}
	if d := p.findOrCreate("root:alice", "conn1", []string{"files:read", "files:write"}, "r"); d.ID == a.ID {
		t.Fatal("a used nonce must never be handed out again")
	}
}

// TestPendingDoneChannelIsSharedAcrossDedup pins the key subtlety of the blocking flow: the
// record minted by a guarded vendor call's denial and the record the model's follow-up
// request_access blocks on are the SAME record — the done channel is created exactly once,
// in the mint branch, and every copy shares it.
func TestPendingDoneChannelIsSharedAcrossDedup(t *testing.T) {
	now := int64(1000)
	p := newTestStore(&now)
	a := p.findOrCreate("root:alice", "conn1", []string{"files:read"}, "tool: read_file")
	if a.done == nil {
		t.Fatal("findOrCreate must mint a done channel")
	}
	b := p.findOrCreate("root:alice", "conn1", []string{"files:read"}, "request_access")
	if a.done != b.done {
		t.Fatal("deduped record must share ONE done channel — the vendor-denial record and the blocked request_access must resolve together")
	}
	// consume's copy shares it too: submit resolves the exact channel the waiter holds.
	c, err := p.consume(a.ID, a.WidgetToken, "conn1", "root:alice")
	if err != nil {
		t.Fatalf("consume failed: %v", err)
	}
	if c.done != a.done {
		t.Fatal("consumed copy must carry the same done channel")
	}
}

func TestAwaitConsentGranted(t *testing.T) {
	now := int64(1000)
	p := newTestStore(&now)
	pc := p.findOrCreate("root:alice", "conn1", []string{"files:read"}, "r")

	// The submit arrives 100ms after request_access started blocking.
	go func() {
		time.Sleep(100 * time.Millisecond)
		got, err := p.consume(pc.ID, pc.WidgetToken, "conn1", "root:alice")
		if err != nil {
			t.Errorf("consume failed: %v", err)
			return
		}
		got.resolve(consentOutcome{granted: true, message: "Granted. session sess_x is live."})
	}()

	o, ok := awaitConsent(context.Background(), pc.done, 5*time.Second)
	if !ok {
		t.Fatal("awaitConsent must return the outcome, not time out")
	}
	if !o.granted || !strings.Contains(o.message, "Granted") {
		t.Fatalf("waiter must receive the grant outcome verbatim, got: %+v", o)
	}
}

func TestAwaitConsentDenied(t *testing.T) {
	now := int64(1000)
	p := newTestStore(&now)
	pc := p.findOrCreate("root:alice", "conn1", []string{"files:read"}, "r")

	go func() {
		time.Sleep(100 * time.Millisecond)
		pc.resolve(consentOutcome{granted: false, message: "Denied. nothing was granted"})
	}()

	o, ok := awaitConsent(context.Background(), pc.done, 5*time.Second)
	if !ok || o.granted || !strings.Contains(o.message, "Denied") {
		t.Fatalf("waiter must receive the denial outcome, got ok=%v %+v", ok, o)
	}
}

func TestAwaitConsentTimesOut(t *testing.T) {
	now := int64(1000)
	p := newTestStore(&now)
	pc := p.findOrCreate("root:alice", "conn1", []string{"files:read"}, "r")

	start := time.Now()
	if _, ok := awaitConsent(context.Background(), pc.done, 50*time.Millisecond); ok {
		t.Fatal("no decision was submitted — awaitConsent must report a timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the short timer override was not honored")
	}
	// A late resolve after the timeout parks in the buffered channel — never blocks the
	// submitter, and the waiter's post-timeout drain can still pick it up.
	pc.resolve(consentOutcome{granted: true, message: "late"})
	select {
	case o := <-pc.done:
		if !o.granted {
			t.Fatalf("drained outcome mangled: %+v", o)
		}
	default:
		t.Fatal("late resolve must park the outcome in the buffered channel")
	}
}

func TestAwaitConsentContextCancel(t *testing.T) {
	now := int64(1000)
	p := newTestStore(&now)
	pc := p.findOrCreate("root:alice", "conn1", []string{"files:read"}, "r")

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if _, ok := awaitConsent(ctx, pc.done, 5*time.Second); ok {
		t.Fatal("a cancelled request context must end the wait with ok=false")
	}
}

// TestPendingWaitingFlag pins the delivered_inline signal: consume snapshots waiting as set
// by the blocked request_access, and setWaiting on a gone id is a harmless no-op.
func TestPendingWaitingFlag(t *testing.T) {
	now := int64(1000)
	p := newTestStore(&now)
	pc := p.findOrCreate("root:alice", "conn1", []string{"files:read"}, "r")

	p.setWaiting(pc.ID, true)
	got, err := p.consume(pc.ID, pc.WidgetToken, "conn1", "root:alice")
	if err != nil {
		t.Fatalf("consume failed: %v", err)
	}
	if !got.waiting {
		t.Fatal("consume must snapshot waiting=true while a request_access call is blocked")
	}
	p.setWaiting("no-such-id", true) // must not panic

	pc2 := p.findOrCreate("root:alice", "conn2", []string{"files:read"}, "r")
	got2, err := p.consume(pc2.ID, pc2.WidgetToken, "conn2", "root:alice")
	if err != nil {
		t.Fatalf("consume failed: %v", err)
	}
	if got2.waiting {
		t.Fatal("with no blocked waiter, consume must snapshot waiting=false")
	}
}

func TestPendingExpiredRecordIsNotReused(t *testing.T) {
	now := int64(1000)
	p := newTestStore(&now)
	a := p.findOrCreate("root:alice", "conn1", []string{"files:read"}, "r")
	now = 1000 + pendingTTL.Milliseconds() + 1
	b := p.findOrCreate("root:alice", "conn1", []string{"files:read"}, "r")
	if a.ID == b.ID {
		t.Fatal("an expired record must be pruned, not reused")
	}
}
