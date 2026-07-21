// Package rootkeys custodies each principal's OWN root signing key. A principal (a registered
// user or org) mints its root slips with its own ed25519 key: the public key is stored in the
// clear (to verify what it issued), the private key sealed with the master key (never
// plaintext in the DB). There is no shared process-wide root key.
//
// It satisfies controlplane.RootKeys — Signer(principal) for minting, Public(principal) for
// verification — and adds Ensure(principal), which lazily generates and stores a keypair the
// first time (idempotent: an existing key is preserved, so re-seeding never rotates a key or
// orphans a principal's live sessions). A KMS-backed custodian would implement the same port.
package rootkeys

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"

	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/store"
	core "delegent.dev/protocol"
)

// Store resolves and custodies per-principal root keys over a store.Store and a keyring.Sealer.
type Store struct {
	st     store.Store
	sealer keyring.Sealer

	mu      sync.Mutex
	signers map[string]core.Signer // cache: principal -> its signer
	pubs    map[string]string      // cache: principal -> its public key (hex)
}

// New builds a custodian over the given store and sealer.
func New(st store.Store, sealer keyring.Sealer) *Store {
	return &Store{st: st, sealer: sealer, signers: map[string]core.Signer{}, pubs: map[string]string{}}
}

func bg() context.Context { return context.Background() }

// Ensure generates and stores a root keypair for the user if it has none, and returns its
// public key. Idempotent: a user that already holds a key keeps it (only the key fields are
// ever touched). The user row must already exist.
func (s *Store) Ensure(ctx context.Context, user string) (string, error) {
	u, err := s.st.GetUser(ctx, user)
	if err != nil {
		return "", fmt.Errorf("user %q: %w", user, err)
	}
	if u.Pubkey != "" && len(u.SealedKey) > 0 {
		return u.Pubkey, nil // already has a key — preserve it
	}
	pub, priv, err := core.NewKeypair()
	if err != nil {
		return "", err
	}
	sealed, err := s.sealer.Seal(priv)
	if err != nil {
		return "", err
	}
	u.Pubkey = pub
	u.SealedKey = sealed
	if err := s.st.PutUser(ctx, u); err != nil {
		return "", err
	}
	return pub, nil
}

// Signer returns the user's signing key for minting, unsealing it on first use.
func (s *Store) Signer(user string) (core.Signer, error) {
	s.mu.Lock()
	if sg, ok := s.signers[user]; ok {
		s.mu.Unlock()
		return sg, nil
	}
	s.mu.Unlock()

	u, err := s.st.GetUser(bg(), user)
	if err != nil {
		return nil, fmt.Errorf("user %q: %w", user, err)
	}
	if len(u.SealedKey) == 0 {
		return nil, fmt.Errorf("user %q has no root key", user)
	}
	priv, err := s.sealer.Unseal(u.SealedKey)
	if err != nil {
		return nil, fmt.Errorf("unseal %q root key: %w", user, err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("user %q key is %d bytes, want %d", user, len(priv), ed25519.PrivateKeySize)
	}
	sg := core.NewEd25519Signer(ed25519.PrivateKey(priv))
	s.mu.Lock()
	s.signers[user] = sg
	s.pubs[user] = u.Pubkey
	s.mu.Unlock()
	return sg, nil
}

// Public returns the user's public key (hex), for verifying slips it issued.
func (s *Store) Public(user string) (string, bool) {
	s.mu.Lock()
	if pub, ok := s.pubs[user]; ok {
		s.mu.Unlock()
		return pub, true
	}
	s.mu.Unlock()

	u, err := s.st.GetUser(bg(), user)
	if err != nil || u.Pubkey == "" {
		return "", false
	}
	s.mu.Lock()
	s.pubs[user] = u.Pubkey
	s.mu.Unlock()
	return u.Pubkey, true
}
