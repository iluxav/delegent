package controlplane

import (
	"context"
	"testing"

	core "delegent.dev/protocol"
	"delegent.dev/gateway/store"
)

// TestReceipts_ChainAndSign drives record twice for the same principal and asserts the
// receipts form a signed hash chain: receipt 2 links to receipt 1, both hashes are
// non-empty and reproducible, and both signatures verify under the principal's root key.
func TestReceipts_ChainAndSign(t *testing.T) {
	cp := newCP(t)

	cp.record(store.Receipt{Principal: "root:alice", Tool: "request_access", Decision: "deny", Reason: "first", Scopes: []string{"files:read", "mcp:connect"}})
	cp.record(store.Receipt{Principal: "root:alice", Tool: "request_access", Decision: "grant", Reason: "second", Scopes: []string{"files:read"}})

	rs, err := cp.o.Store.ListReceipts(context.Background(), store.ReceiptFilter{Principal: "root:alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(rs))
	}
	r1, r2 := rs[0], rs[1]

	if r1.PrevHash != "" {
		t.Errorf("first receipt should root the chain, PrevHash=%q", r1.PrevHash)
	}
	if r1.Hash == "" || r2.Hash == "" {
		t.Fatalf("both receipts must carry a hash: r1=%q r2=%q", r1.Hash, r2.Hash)
	}
	if r2.PrevHash != r1.Hash {
		t.Errorf("chain broken: r2.PrevHash=%q, want r1.Hash=%q", r2.PrevHash, r1.Hash)
	}

	if got := receiptHash(r1, ""); got != r1.Hash {
		t.Errorf("r1 hash not reproducible: got %q, stored %q", got, r1.Hash)
	}
	if got := receiptHash(r2, r1.Hash); got != r2.Hash {
		t.Errorf("r2 hash not reproducible: got %q, stored %q", got, r2.Hash)
	}

	pub, ok := cp.o.RootKeys.Public("root:alice")
	if !ok {
		t.Fatal("no public key for root:alice")
	}
	if !core.VerifyBytes(pub, []byte(r1.Hash), r1.Sig) {
		t.Error("r1 signature does not verify")
	}
	if !core.VerifyBytes(pub, []byte(r2.Hash), r2.Sig) {
		t.Error("r2 signature does not verify")
	}
}

// TestReceipts_PerPrincipalChains proves each principal has an independent chain: a receipt
// for principal B roots its own chain regardless of principal A's history.
func TestReceipts_PerPrincipalChains(t *testing.T) {
	cp := newCP(t)

	cp.record(store.Receipt{Principal: "root:alice", Tool: "request_access", Decision: "deny", Reason: "a1"})
	cp.record(store.Receipt{Principal: "root:alice", Tool: "request_access", Decision: "deny", Reason: "a2"})
	cp.record(store.Receipt{Principal: "root:bob", Tool: "request_access", Decision: "deny", Reason: "b1"})

	bob, err := cp.o.Store.ListReceipts(context.Background(), store.ReceiptFilter{Principal: "root:bob"})
	if err != nil {
		t.Fatal(err)
	}
	if len(bob) != 1 {
		t.Fatalf("expected 1 bob receipt, got %d", len(bob))
	}
	if bob[0].PrevHash != "" {
		t.Errorf("bob's chain must be independent of alice's, PrevHash=%q", bob[0].PrevHash)
	}
	if bob[0].Hash == "" {
		t.Error("bob's receipt must still be hashed")
	}
}
