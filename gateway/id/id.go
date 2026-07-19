// Package id generates prefixed NanoIDs — short, URL-safe, collision-resistant public
// identifiers (Stripe-style: "sess_V1StGXR8Zx7pq"). They are the primary keys for runtime
// entities, friendlier to read and copy than a UUID while carrying far more entropy than the
// old randHex(4) handles (which collided around ~65k rows).
package id

import (
	"crypto/rand"
	"strings"
)

// alphabet is exactly 64 URL-safe characters. Because 256 is divisible by 64, mapping a random
// byte through (b & 63) is perfectly uniform — no modulo bias, no rejection sampling needed.
const alphabet = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"

// Size is the number of random characters after the prefix. 16 chars over a 64-symbol alphabet
// is 96 bits of entropy — collision-safe well past any realistic row count.
const Size = 16

// NanoID returns a bare random id of n characters.
func NanoID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	out := make([]byte, n)
	for i, c := range b {
		out[i] = alphabet[c&63]
	}
	return string(out)
}

// New returns a prefixed id: "<prefix>_<nanoid>", e.g. New("sess") -> "sess_V1StGXR8Zx7pq".
func New(prefix string) string {
	return prefix + "_" + NanoID(Size)
}

// Prefix returns the type prefix of an id (the part before the first underscore), or "".
func Prefix(id string) string {
	if i := strings.IndexByte(id, '_'); i >= 0 {
		return id[:i]
	}
	return ""
}
