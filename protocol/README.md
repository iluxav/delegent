# delegent.dev/protocol

The reference implementation of the **Delegent protocol**: consent-bound, attenuable,
audience-bound capability slips for AI-agent authority — plus the tamper-evident receipt
chains that audit every decision made under them.

This library is the math. It has **zero dependencies** (Go standard library only) and holds no
state, no I/O, and no keys of its own — any party can verify a chain or a receipt trail with
nothing but this package and a public key. The [Delegent gateway](../gateway) and the hosted
platform at [delegent.dev](https://delegent.dev) build on it; so can anyone else.

## The model in five sentences

An operator's **root key** signs a **slip**: a statement of limits — scopes, effects, budget,
expiry, sub-delegation depth — bound to one agent's public key (`aud`). The agent may **narrow**
its slip into a strictly-weaker child bound to another agent's key, offline, without contacting
anyone; the signed **chain** travels with the request. A verifier **folds** the chain — every
link is intersected, so no child can ever exceed its parent — and checks signatures, linkage,
expiry, depth, and the caller's **proof of possession** of the bound key, which makes a stolen
chain useless. Every decision taken under a slip is recorded as a **receipt**, hash-chained per
principal and signed by the root key, so dropped, reordered, or altered records are detectable
by anyone holding the public key. Revocation is enforced wherever the chain is redeemed — the
issuer's gateway — so it is local and instant.

## Library

```go
import protocol "delegent.dev/protocol"

pub, priv, _ := protocol.NewKeypair()
slip, _ := protocol.SignSlip(protocol.SlipBody{ /* limits */ }, protocol.NewEd25519Signer(priv))
chain, anomalies, _ := protocol.Narrow(parent, caveats, childPub, parentSigner, nonce)
res := protocol.VerifyChain(chain, callerPub, callerSig, reqBytes, roots, now)
status := protocol.VerifyReceiptChain(receipts, rootPub)
```

Key entry points: `SignSlip`, `Narrow`, `Fold`, `VerifyChain`, `Authorize`, `Classify`,
`ReceiptHash`, `VerifyReceiptChain`, `Canonical`. Conformance vectors live in `testdata/`.

## CLI

`cmd/delegent` is the protocol in a terminal — the same operations, file-shaped:

```sh
go install delegent.dev/protocol/cmd/delegent@latest

delegent keygen                                  # {"pub": …, "priv": …}
delegent mint --priv K --iss root:alice --aud AGENT_PUB \
  --vendor github --scopes repos:read,repos:write --effects read,write \
  --ceiling repos:admin --methods GET,POST --resources '/repos/*' \
  --budget 10 --ttl-minutes 60 --depth 2 > chain.json
delegent attenuate --chain chain.json --priv AGENT_PRIV \
  --aud REMOTE_PUB --scopes repos:read --ceiling repos:read --budget 2 > child.json
delegent inspect --chain child.json              # per-link view + folded limits
delegent verify --chain child.json --root root:alice=ROOT_PUB \
  --priv REMOTE_PRIV                             # full verify (proof-of-possession)
delegent verify --chain child.json --root root:alice=ROOT_PUB
                                                 # structural verify (auditor's view)
delegent hash-receipts --receipts raw.json --priv ROOT_PRIV > signed.json
                                                 # chain + SIGN receipts (omit --priv to
                                                 # hash only; stale sigs are stripped loudly)
delegent verify-receipts --receipts signed.json --pub ROOT_PUB
```

Exit code 0 = verified; non-zero = refused, with the specific reason on stderr — the reasons
are the audit trail.

## License

Apache-2.0 — see [LICENSE](LICENSE).
