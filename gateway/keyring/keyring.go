// Package keyring seals secret bytes before they are persisted — per-session holder private
// keys, per-principal root signing keys, and vendor credentials — so raw secrets never land
// in the database. It is the port through which the broker turns an in-memory
// ed25519 key into opaque bytes for the Store and back again. The default implementation is
// AES-256-GCM under a master key; the same Sealer interface is satisfied by a KMS-backed
// implementation later, with zero call-site changes.
//
// The master key is loaded from DELEGENT_MASTER_KEY (base64 of 32 bytes). For local
// development, an unset key falls back to a fixed dev key with a loud warning — never rely on
// that in production, where the master key belongs in KMS or a secret manager.
package keyring

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

// Sealer seals and unseals secret bytes. Seal output is opaque and self-describing (it carries
// its own nonce); Unseal fails closed on any tampering.
type Sealer interface {
	Seal(plaintext []byte) ([]byte, error)
	Unseal(sealed []byte) ([]byte, error)
}

// aesSealer is AES-256-GCM. Sealed layout is nonce || ciphertext||tag.
type aesSealer struct{ aead cipher.AEAD }

// NewAESSealer builds a Sealer from a 32-byte key.
func NewAESSealer(key []byte) (Sealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("keyring: master key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &aesSealer{aead: aead}, nil
}

// devKey is the fixed fallback used only when DELEGENT_MASTER_KEY is unset. It is intentionally
// not secret — a local dev convenience so the gateway boots without ceremony.
var devKey = []byte("delegent-dev-master-key-32-bytes") // exactly 32 bytes

// IsDev reports whether key is the built-in dev fallback. The gateway refuses to run with it
// while agent-key auth is on — a public master key would let anyone unseal every stored
// credential and session key.
func IsDev(key []byte) bool {
	return subtle.ConstantTimeCompare(key, devKey) == 1
}

// MasterKey returns the 32-byte master key from DELEGENT_MASTER_KEY (base64), or the dev key
// (with a warning) when unset. This one stable key both seals session keys and derives the
// root signing key, so a restart can unseal and verify what a prior run wrote.
func MasterKey() ([]byte, error) {
	raw := os.Getenv("DELEGENT_MASTER_KEY")
	if raw == "" {
		log.Printf("⚠️ keyring: DELEGENT_MASTER_KEY unset — using the built-in DEV key. Do NOT use this in production.")
		return append([]byte(nil), devKey...), nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("keyring: DELEGENT_MASTER_KEY is not valid base64: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("keyring: DELEGENT_MASTER_KEY must decode to 32 bytes, got %d", len(key))
	}
	return key, nil
}

// FromEnv builds a Sealer from the master key.
func FromEnv() (Sealer, error) {
	key, err := MasterKey()
	if err != nil {
		return nil, err
	}
	return NewAESSealer(key)
}

func (s *aesSealer) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *aesSealer) Unseal(sealed []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(sealed) < ns {
		return nil, errors.New("keyring: sealed value too short")
	}
	nonce, ct := sealed[:ns], sealed[ns:]
	return s.aead.Open(nil, nonce, ct, nil)
}
