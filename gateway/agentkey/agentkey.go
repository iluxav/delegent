// Package agentkey generates and hashes agent keys — the `dgk_…` tokens an agent presents to
// the gateway to authenticate as a user. Only the sha256 hash is ever stored; the plaintext is
// shown to the operator exactly once at creation and is otherwise unrecoverable.
package agentkey

import (
	"crypto/sha256"

	"delegent.dev/gateway/id"
)

// Prefix is the human-recognizable scheme prefix of every agent key.
const Prefix = "dgk_"

// New returns a fresh key: the full token (shown once), its sha256 hash (stored), and a short
// display prefix.
func New() (full string, hash []byte, prefix string) {
	full = Prefix + id.NanoID(32)
	hash = Hash(full)
	prefix = full[:12] // "dgk_" + 8 chars
	return
}

// Hash returns the sha256 of a token, for storage and lookup.
func Hash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}
