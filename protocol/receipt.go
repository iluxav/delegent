package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// Receipt is one decision record in a principal's tamper-evident chain: what was decided
// (grant/deny/flag), for which tool and scopes, when — hash-chained per principal and signed
// by the principal's root key. This is the protocol-level shape: any party holding a chain of
// these and the principal's public key can verify integrity, ordering, and authenticity with
// VerifyReceiptChain — no platform required.
type Receipt struct {
	ID        string   `json:"id"`
	Principal string   `json:"principal"`
	Handle    string   `json:"handle,omitempty"`
	Tool      string   `json:"tool,omitempty"`     // the tool or action decided on
	Decision  string   `json:"decision"`           // "grant" | "deny" | "flag"
	Reason    string   `json:"reason,omitempty"`   //
	Effect    string   `json:"effect,omitempty"`   // rendered effect names, e.g. "read+write"
	Scopes    []string `json:"scopes,omitempty"`   //
	OverAsk   bool     `json:"over_ask,omitempty"` //
	CreatedAt int64    `json:"created_at"`         // unix ms

	// PrevHash/Hash/Sig form the chain: Hash = H(canonical fields ‖ PrevHash), Sig =
	// ed25519(rootKey, Hash). An empty Sig marks a fail-soft unsigned mint.
	PrevHash string `json:"prev_hash,omitempty"`
	Hash     string `json:"hash"`
	Sig      string `json:"sig,omitempty"`
}

// receiptSep joins the canonical fields; a field can never contain it ambiguously because
// every field is either an id, an enum, a number, or a sorted comma-joined scope list.
const receiptSep = "\x1f"

// ReceiptHash computes the canonical hash of one receipt folded with the prior chain hash.
// Field order and separators are fixed, and Scopes are sorted first, so neither scope ordering
// nor field concatenation can change the hash for the same logical receipt. It deliberately
// excludes Hash/Sig/PrevHash themselves — prev IS the prior receipt's hash.
func ReceiptHash(r *Receipt, prev string) string {
	scopes := append([]string(nil), r.Scopes...)
	sort.Strings(scopes)
	overAsk := "0"
	if r.OverAsk {
		overAsk = "1"
	}
	fields := []string{
		r.ID,
		r.Principal,
		r.Handle,
		r.Tool,
		r.Decision,
		r.Reason,
		r.Effect,
		strings.Join(scopes, ","),
		overAsk,
		strconv.FormatInt(r.CreatedAt, 10),
		prev,
	}
	sum := sha256.Sum256([]byte(strings.Join(fields, receiptSep)))
	return hex.EncodeToString(sum[:])
}

// ChainStatus is the verdict of walking one principal's receipt chain: whether it is intact,
// how many receipts were checked, and — on the first break — which receipt failed and why.
// Unsigned counts receipts that carry no signature (a legitimate fail-soft mint), which is a
// soft warning rather than a hard chain break.
type ChainStatus struct {
	Verified bool   `json:"verified"`
	Count    int    `json:"count"`
	BrokenAt string `json:"broken_at,omitempty"` // receipt ID where verification first failed
	Reason   string `json:"reason,omitempty"`
	Unsigned int    `json:"unsigned,omitempty"` // count of unsigned receipts (soft)
}

// VerifyReceiptChain walks receipts oldest→newest (chain order for ONE principal) and returns
// the first break, if any. pub is that principal's public key (hex).
//
// Per receipt, in order:
//   - linkage: PrevHash must equal the prior receipt's Hash ("" for the first) — a mismatch
//     means a receipt was dropped or reordered.
//   - integrity: the recomputed hash must equal the stored Hash — a mismatch means a field was
//     altered.
//   - authenticity: a non-empty Sig must verify under pub. An empty Sig is a legitimate
//     unsigned receipt (fail-soft mint): counted and skipped, never a hard break, as long as
//     its hash and linkage hold.
func VerifyReceiptChain(receipts []Receipt, pub string) ChainStatus {
	st := ChainStatus{Verified: true, Count: len(receipts)}
	prevSeen := ""
	for i := range receipts {
		r := &receipts[i]
		if r.PrevHash != prevSeen {
			return ChainStatus{Verified: false, Count: len(receipts), BrokenAt: r.ID, Unsigned: st.Unsigned,
				Reason: "prev-hash mismatch — a receipt was dropped or reordered"}
		}
		if ReceiptHash(r, r.PrevHash) != r.Hash {
			return ChainStatus{Verified: false, Count: len(receipts), BrokenAt: r.ID, Unsigned: st.Unsigned,
				Reason: "hash mismatch — a field was altered"}
		}
		if r.Sig == "" {
			st.Unsigned++
		} else if !VerifyBytes(pub, []byte(r.Hash), r.Sig) {
			return ChainStatus{Verified: false, Count: len(receipts), BrokenAt: r.ID, Unsigned: st.Unsigned,
				Reason: "signature invalid"}
		}
		prevSeen = r.Hash
	}
	return st
}
