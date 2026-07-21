package gateway

// MCP lifecycle handling around consent waits: an agent that CANCELS a call (or whose
// connection dies) mid-wait withdraws the parked ask — no ghost asks a human can approve
// into the void — and a call that supplied a progressToken sees why it is blocked.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestConsoleCancelWithdrawsAsk: cancelling the request context during the sync window
// removes the live record, finalizes the durable row as "cancelled", and publishes a
// resolve event so dashboards clear their badges.
func TestConsoleCancelWithdrawsAsk(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	g.consoleConsent = true
	g.syncWait = 5 * time.Second // long window: cancellation must end the wait, not the timer
	g.hub = newConsentHub()
	events, cancelSub := g.hub.subscribe()
	defer cancelSub()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel() // the agent abandons the call — MCP cancellation maps to ctx cancellation
	}()

	start := time.Now()
	res := g.consoleConsentBlock(ctx, "conn1", "read_file", []string{"files:read"}, callMeta{Tool: "read_file", Target: g.targetID})
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancellation must end the wait immediately, not after the sync window")
	}
	if res == nil || !res.IsError {
		t.Fatalf("a cancelled wait must not read as success: %+v", res)
	}
	if txt := resultText(res); !containsFold(txt, "cancelled") {
		t.Fatalf("result should say the request was cancelled, got %q", txt)
	}

	// live record gone
	if live := g.pending.listLive(); len(live) != 0 {
		t.Fatalf("withdrawn ask still live: %+v", live)
	}
	// durable row finalized as cancelled (audit trail), no longer pending
	rows, err := g.st.ListConsentRequests(context.Background(), "root:alice", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Status != "cancelled" || rows[0].ResolvedAt == 0 {
		t.Fatalf("expected one cancelled row with ResolvedAt set, got: %+v", rows)
	}
	if pend, _ := g.st.ListConsentRequests(context.Background(), "root:alice", false); len(pend) != 0 {
		t.Fatalf("cancelled ask still listed pending: %+v", pend)
	}

	// subscribers saw pending then resolved — the badge lifecycle
	sawPending, sawResolved := false, false
	deadline := time.After(time.Second)
	for !(sawPending && sawResolved) {
		select {
		case ev := <-events:
			switch ev.Type {
			case "pending":
				sawPending = true
			case "resolved":
				sawResolved = true
			}
		case <-deadline:
			t.Fatalf("hub events incomplete: pending=%v resolved=%v", sawPending, sawResolved)
		}
	}
}

// TestConsoleCancelRaceDecisionWins: a decision that lands just as the agent cancels is
// preserved — withdraw skips used records, so the audit trail keeps the human's decision.
func TestConsoleCancelRaceDecisionWins(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	g.consoleConsent = true
	g.syncWait = 40 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.consoleConsentBlock(ctx, "conn1", "read_file", []string{"files:read"}, callMeta{Tool: "read_file", Target: g.targetID})

	// wait for the record, resolve it (burn the nonce), THEN cancel
	var id string
	for i := 0; i < 100; i++ {
		if live := g.pending.listLive(); len(live) == 1 {
			id = live[0].ID
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("ask never parked")
	}
	if _, err := g.pending.consumeByID(id, "root:alice"); err != nil {
		t.Fatal(err)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	if g.pending.withdraw(id) {
		t.Fatal("withdraw must skip an already-used (decided) record")
	}
}

// TestConsoleWaitEmitsProgress: a call that asked for progress gets an immediate
// "waiting for human approval" message naming the request id.
func TestConsoleWaitEmitsProgress(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	g.consoleConsent = true
	g.syncWait = 30 * time.Millisecond

	var mu sync.Mutex
	var msgs []string
	ctx := withProgressFn(context.Background(), func(m string) {
		mu.Lock()
		msgs = append(msgs, m)
		mu.Unlock()
	})
	g.consoleConsentBlock(ctx, "conn1", "read_file", []string{"files:read"}, callMeta{Tool: "read_file", Target: g.targetID})

	mu.Lock()
	defer mu.Unlock()
	if len(msgs) == 0 {
		t.Fatal("no progress emitted during the consent wait")
	}
	if !strings.Contains(msgs[0], "waiting for human approval") || !strings.Contains(msgs[0], "creq_") && !strings.Contains(msgs[0], "files:read") {
		t.Fatalf("first progress message should explain the wait: %q", msgs[0])
	}
}
