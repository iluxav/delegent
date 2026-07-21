package controlplane

import (
	"context"
	"sort"

	"delegent.dev/gateway/store"
	core "delegent.dev/protocol"
)

// ChainStatus is the protocol-level chain verdict — re-exported so platform callers (API DTOs,
// gateway) keep their names while the math lives in the protocol library.
type ChainStatus = core.ChainStatus

// VerifyReceipts adapts the platform's stored receipts onto core.VerifyReceiptChain — the
// chain math itself is protocol-level and lives in the protocol library (any holder of the chain and
// the principal's public key can verify without platform types).
func VerifyReceipts(receipts []*store.Receipt, pub string) ChainStatus {
	rs := make([]core.Receipt, len(receipts))
	for i, r := range receipts {
		rs[i] = coreReceipt(r)
	}
	return core.VerifyReceiptChain(rs, pub)
}

// VerifyReceiptsFor loads principal's receipts in chain order (oldest→newest) and verifies the
// chain under that principal's public key. It is the control-plane entry point the gateway calls
// so the gateway stays thin. A missing public key is treated as an unknown principal: the chain
// verifies structurally and every signed receipt fails authenticity — so we surface the receipts
// but report the empty-key case as unverifiable via VerifyReceipts' own signature check.
func (cp *ControlPlane) VerifyReceiptsFor(principal string) ChainStatus {
	rs, err := cp.o.Store.ListReceipts(context.Background(), store.ReceiptFilter{Principal: principal})
	if err != nil {
		return ChainStatus{Verified: false, Reason: "could not load receipts"}
	}
	// Stable sort by CreatedAt keeps the store's natural (insertion / created_at) order for ties.
	// IDs are random NanoIDs — not monotonic — so they can't serve as a reliable tiebreak; the
	// store already returns receipts in append order per principal, which IS the chain order.
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].CreatedAt < rs[j].CreatedAt })
	pub, _ := cp.PublicKeyOf(principal)
	return VerifyReceipts(rs, pub)
}
