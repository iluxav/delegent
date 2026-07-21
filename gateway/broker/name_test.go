package broker_test

import (
	"context"
	"strconv"
	"testing"

	"delegent.dev/gateway/broker"
	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/store"
)

// nameBroker builds a broker over a store the test can seed directly — AgentDisplayName only
// reads Handle/ParentHandle, so sessions can be fabricated without minting real chains.
func nameBroker(t *testing.T) (*broker.Broker, *store.MemStore) {
	t.Helper()
	st := store.NewMemStore()
	sealer, _ := keyring.NewAESSealer([]byte("delegent-dev-master-key-32-bytes"))
	return broker.New(nil, st, sealer, func() int64 { return 1000 }, func() string { return "r" }), st
}

func putSess(t *testing.T, st *store.MemStore, handle, parent string) {
	t.Helper()
	if err := st.PutSession(context.Background(), &store.Session{Handle: handle, Principal: "root:alice", ParentHandle: parent}); err != nil {
		t.Fatal(err)
	}
}

func TestAgentDisplayName(t *testing.T) {
	b, st := nameBroker(t)
	putSess(t, st, "sess_11112222", "")              // root
	putSess(t, st, "sess_33334444", "sess_11112222") // child
	putSess(t, st, "sess_55556666", "sess_33334444") // grandchild
	putSess(t, st, "sess_77778888", "sess_gone")     // parent missing from the store

	cases := []struct{ handle, want string }{
		{"", "new agent connection"},
		{"sess_11112222", "main-agent-11112222"},
		{"sess_33334444", "main-agent-11112222→sub-agent-33334444"},
		{"sess_55556666", "main-agent-11112222→sub-agent-33334444→sub-agent-55556666"},
		{"sess_77778888", "sess_77778888"}, // missing parent → bare handle fallback
		{"sess_nowhere", "sess_nowhere"},   // unknown handle → bare handle fallback
	}
	for _, c := range cases {
		if got := b.AgentDisplayName(c.handle); got != c.want {
			t.Errorf("AgentDisplayName(%q) = %q, want %q", c.handle, got, c.want)
		}
	}
}

func TestAgentDisplayNameDepthCap(t *testing.T) {
	b, st := nameBroker(t)
	// A 7-deep chain: sess_d0000000 (root) → … → sess_d0000006 (leaf).
	parent := ""
	for i := 0; i <= 6; i++ {
		h := "sess_d000000" + strconv.Itoa(i)
		putSess(t, st, h, parent)
		parent = h
	}
	got := b.AgentDisplayName("sess_d0000006")
	// Capped at 5 links, truncated marker in front, and NO main-agent claim — the walk never
	// reached the real root.
	want := "…→sub-agent-d0000002→sub-agent-d0000003→sub-agent-d0000004→sub-agent-d0000005→sub-agent-d0000006"
	if got != want {
		t.Errorf("depth-capped name = %q, want %q", got, want)
	}
}
