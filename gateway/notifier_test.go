package gateway

import (
	"sync"
	"testing"
	"time"

	"delegent.dev/gateway/store"
)

type fakeNotifier struct {
	mu     sync.Mutex
	parked []*store.ConsentRequest
}

func (f *fakeNotifier) ConsentParked(r *store.ConsentRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.parked = append(f.parked, r)
}

func (f *fakeNotifier) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.parked)
}

// persistPending is where a durable console consent request is born — the notifier seam fires
// there, best-effort, with the same record that was stored.
func TestPersistPendingNotifies(t *testing.T) {
	st := store.NewMemStore()
	fn := &fakeNotifier{}
	g := &Gateway{targetID: "gh", st: st, notifier: fn}

	g.persistPending(pendingConsent{
		ID: "creq_1", Principal: "usr_op", Scopes: []string{"files:write"},
		Reason: "tool: write_file", CreatedAt: 1, ExpiresAt: 9_000_000_000_000,
	}, "claude-code")

	deadline := time.Now().Add(2 * time.Second)
	for fn.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	fn.mu.Lock()
	defer fn.mu.Unlock()
	if len(fn.parked) != 1 {
		t.Fatalf("notifier calls = %d, want 1", len(fn.parked))
	}
	r := fn.parked[0]
	if r.ID != "creq_1" || r.Principal != "usr_op" || r.AgentName != "claude-code" {
		t.Fatalf("notified record: %+v", r)
	}
}

// A nil notifier (dev, tests, no telegram configured) must be a silent no-op.
func TestPersistPendingNilNotifier(t *testing.T) {
	g := &Gateway{targetID: "gh", st: store.NewMemStore()}
	g.persistPending(pendingConsent{ID: "creq_2", Principal: "usr_op", CreatedAt: 1, ExpiresAt: 2}, "a")
	// reaching here without a panic is the assertion
}
