package controlplane

import (
	core "delegent.dev/protocol"

	"delegent.dev/gateway/store"
)

// coreReceipt maps the platform's stored receipt onto the protocol-level core.Receipt so the
// chain math (canonical hashing + verification) lives in the protocol library (delegent.dev/protocol), verifiable by any
// party holding the chain and the principal's public key — no platform types required.
func coreReceipt(r *store.Receipt) core.Receipt {
	return core.Receipt{
		ID: r.ID, Principal: r.Principal, Handle: r.Handle, Tool: r.Tool,
		Decision: r.Decision, Reason: r.Reason, Effect: r.Effect, Scopes: r.Scopes,
		OverAsk: r.OverAsk, CreatedAt: r.CreatedAt,
		PrevHash: r.PrevHash, Hash: r.Hash, Sig: r.Sig,
	}
}

// receiptHash delegates to the core canonical hash (see core.ReceiptHash).
func receiptHash(r *store.Receipt, prev string) string {
	cr := coreReceipt(r)
	return core.ReceiptHash(&cr, prev)
}
