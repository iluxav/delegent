package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// The receipt chain is protocol math: per-principal hash-chained, root-key-signed decision
// records. It lives in core so ANY party (the platform, a peer gateway, an auditor with the
// CLI) can verify a chain without platform types.

func signedChain(t *testing.T, priv ed25519.PrivateKey, n int) []Receipt {
	t.Helper()
	var rs []Receipt
	prev := ""
	for i := 0; i < n; i++ {
		r := Receipt{
			ID: "rcpt_" + string(rune('a'+i)), Principal: "root:alice", Tool: "read_file",
			Decision: "grant", Effect: "read", Scopes: []string{"files:read"}, CreatedAt: int64(i + 1),
			PrevHash: prev,
		}
		r.Hash = ReceiptHash(&r, prev)
		r.Sig = hex.EncodeToString(ed25519.Sign(priv, []byte(r.Hash)))
		prev = r.Hash
		rs = append(rs, r)
	}
	return rs
}

func TestVerifyReceiptChainIntact(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rs := signedChain(t, priv, 3)
	st := VerifyReceiptChain(rs, hex.EncodeToString(pub))
	if !st.Verified || st.Count != 3 || st.Unsigned != 0 {
		t.Fatalf("intact chain: %+v", st)
	}
}

func TestVerifyReceiptChainDetectsTamper(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rs := signedChain(t, priv, 3)
	rs[1].Tool = "delete_file" // altered field → recomputed hash mismatch
	st := VerifyReceiptChain(rs, hex.EncodeToString(pub))
	if st.Verified || st.BrokenAt != rs[1].ID {
		t.Fatalf("tamper not caught: %+v", st)
	}
}

func TestVerifyReceiptChainDetectsDrop(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rs := signedChain(t, priv, 3)
	st := VerifyReceiptChain([]Receipt{rs[0], rs[2]}, hex.EncodeToString(pub)) // rs[1] dropped
	if st.Verified || st.BrokenAt != rs[2].ID {
		t.Fatalf("drop not caught: %+v", st)
	}
}

func TestVerifyReceiptChainUnsignedIsSoft(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rs := signedChain(t, priv, 3)
	rs[1].Sig = "" // fail-soft mint: unsigned but hash+linkage intact
	st := VerifyReceiptChain(rs, hex.EncodeToString(pub))
	if !st.Verified || st.Unsigned != 1 {
		t.Fatalf("unsigned should be a soft count: %+v", st)
	}
}

func TestVerifyReceiptChainBadSignature(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rs := signedChain(t, priv, 2)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	st := VerifyReceiptChain(rs, hex.EncodeToString(otherPub))
	if st.Verified || st.Reason == "" {
		t.Fatalf("wrong key must fail authenticity: %+v", st)
	}
}

func TestReceiptHashScopeOrderInvariant(t *testing.T) {
	a := Receipt{ID: "r1", Principal: "p", Scopes: []string{"b", "a"}, CreatedAt: 1}
	b := Receipt{ID: "r1", Principal: "p", Scopes: []string{"a", "b"}, CreatedAt: 1}
	if ReceiptHash(&a, "") != ReceiptHash(&b, "") {
		t.Fatal("scope order must not change the hash")
	}
}
