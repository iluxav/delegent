package controlplane

import (
	"context"
	"strings"
	"testing"

	"delegent.dev/gateway/store"
)

// loadChain records n receipts for principal via the real mint path, then loads them back in
// chain order (MemStore.ListReceipts returns append order = oldest→newest for one principal).
func loadChain(t *testing.T, cp *ControlPlane, principal string, n int) []*store.Receipt {
	t.Helper()
	for i := 0; i < n; i++ {
		cp.record(store.Receipt{
			Principal: principal, Tool: "request_access", Decision: "deny",
			Reason: "step", Scopes: []string{"files:read"},
		})
	}
	rs, err := cp.o.Store.ListReceipts(context.Background(), store.ReceiptFilter{Principal: principal})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != n {
		t.Fatalf("expected %d receipts, got %d", n, len(rs))
	}
	return rs
}

func pubOf(t *testing.T, cp *ControlPlane, principal string) string {
	t.Helper()
	pub, ok := cp.o.RootKeys.Public(principal)
	if !ok {
		t.Fatalf("no public key for %s", principal)
	}
	return pub
}

// TestVerify_CleanChain proves an untouched signed chain verifies end to end.
func TestVerify_CleanChain(t *testing.T) {
	cp := newCP(t)
	rs := loadChain(t, cp, "root:alice", 4)

	st := VerifyReceipts(rs, pubOf(t, cp, "root:alice"))
	if !st.Verified {
		t.Fatalf("clean chain should verify, got %+v", st)
	}
	if st.Count != 4 {
		t.Errorf("Count = %d, want 4", st.Count)
	}
	if st.BrokenAt != "" || st.Reason != "" {
		t.Errorf("clean chain should have no break: %+v", st)
	}
}

// TestVerify_FieldTamperDetected flips a middle receipt's Reason after the fact; the recomputed
// hash no longer matches the stored Hash, so integrity fails AT that receipt.
func TestVerify_FieldTamperDetected(t *testing.T) {
	cp := newCP(t)
	rs := loadChain(t, cp, "root:alice", 4)

	victim := rs[1]
	victim.Reason = "TAMPERED"

	st := VerifyReceipts(rs, pubOf(t, cp, "root:alice"))
	if st.Verified {
		t.Fatal("field tamper must break verification")
	}
	if st.BrokenAt != victim.ID {
		t.Errorf("BrokenAt = %q, want tampered receipt %q", st.BrokenAt, victim.ID)
	}
	if !strings.Contains(st.Reason, "hash mismatch") {
		t.Errorf("Reason = %q, want a hash-mismatch reason", st.Reason)
	}
}

// TestVerify_DropDetected removes a middle receipt; the following receipt's PrevHash no longer
// matches the receipt now preceding it, so linkage breaks.
func TestVerify_DropDetected(t *testing.T) {
	cp := newCP(t)
	rs := loadChain(t, cp, "root:alice", 4)

	// Drop the middle receipt rs[1]; rs[2] now dangles because its PrevHash points at rs[1].Hash.
	dropped := []*store.Receipt{rs[0], rs[2], rs[3]}
	following := rs[2]

	st := VerifyReceipts(dropped, pubOf(t, cp, "root:alice"))
	if st.Verified {
		t.Fatal("a dropped receipt must break the chain")
	}
	if st.BrokenAt != following.ID {
		t.Errorf("BrokenAt = %q, want first dangling receipt %q", st.BrokenAt, following.ID)
	}
	if !strings.Contains(st.Reason, "prev-hash") {
		t.Errorf("Reason = %q, want a prev-hash mismatch", st.Reason)
	}
}

// TestVerify_ReorderDetected swaps two adjacent receipts; linkage no longer holds.
func TestVerify_ReorderDetected(t *testing.T) {
	cp := newCP(t)
	rs := loadChain(t, cp, "root:alice", 4)

	rs[1], rs[2] = rs[2], rs[1]

	st := VerifyReceipts(rs, pubOf(t, cp, "root:alice"))
	if st.Verified {
		t.Fatal("reordering receipts must break the chain")
	}
	if st.BrokenAt == "" {
		t.Error("a break must name the offending receipt")
	}
}

// TestVerify_UnsignedIsSoft proves a chain minted for a principal with no root key (so every
// receipt is unsigned) still verifies structurally, with Unsigned counting the soft warnings.
func TestVerify_UnsignedIsSoft(t *testing.T) {
	cp := newCP(t)
	// "root:carol" was never given a key in newCP, so record fail-softs to unsigned receipts
	// while still computing hashes and linkage.
	rs := loadChain(t, cp, "root:carol", 3)
	for _, r := range rs {
		if r.Sig != "" {
			t.Fatalf("expected unsigned receipts for keyless principal, got Sig=%q", r.Sig)
		}
	}

	st := VerifyReceipts(rs, "") // no pubkey; unsigned receipts skip the sig check
	if !st.Verified {
		t.Fatalf("unsigned chain with intact hashes must still verify: %+v", st)
	}
	if st.Unsigned < 1 {
		t.Errorf("Unsigned = %d, want >= 1", st.Unsigned)
	}
	if st.Count != 3 {
		t.Errorf("Count = %d, want 3", st.Count)
	}
}
