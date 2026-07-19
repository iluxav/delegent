package keyring

import (
	"bytes"
	"testing"
)

func TestSeal_RoundTrip(t *testing.T) {
	s, err := NewAESSealer(devKey)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("an ed25519 private key's 32 bytes")
	sealed, err := s.Seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("sealed value leaks the plaintext")
	}
	out, err := s.Unseal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, secret) {
		t.Fatalf("round-trip mismatch: %q", out)
	}
}

func TestSeal_NonceVariesPerCall(t *testing.T) {
	s, _ := NewAESSealer(devKey)
	a, _ := s.Seal([]byte("same"))
	b, _ := s.Seal([]byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext are identical — nonce not random")
	}
}

func TestUnseal_TamperFailsClosed(t *testing.T) {
	s, _ := NewAESSealer(devKey)
	sealed, _ := s.Seal([]byte("secret"))
	sealed[len(sealed)-1] ^= 0xff // flip a tag bit
	if _, err := s.Unseal(sealed); err == nil {
		t.Fatal("tampered ciphertext must not unseal")
	}
}

func TestIsDev(t *testing.T) {
	if !IsDev(devKey) {
		t.Fatal("devKey itself must be recognized as the dev key")
	}
	if !IsDev(append([]byte(nil), devKey...)) {
		t.Fatal("a copy of the dev key (as MasterKey returns) must be recognized")
	}
	other := bytes.Repeat([]byte{0x42}, 32)
	if IsDev(other) {
		t.Fatal("a real 32-byte key must not be flagged as dev")
	}
	if IsDev(devKey[:31]) {
		t.Fatal("a truncated key must not be flagged as dev")
	}
}

func TestNewAESSealer_RejectsWrongKeyLen(t *testing.T) {
	if _, err := NewAESSealer([]byte("short")); err == nil {
		t.Fatal("want error for non-32-byte key")
	}
}
