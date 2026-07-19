package secretstore

import (
	"context"
	"testing"

	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/store"
)

func testSealer(t *testing.T) keyring.Sealer {
	t.Helper()
	s, err := keyring.NewAESSealer([]byte("delegent-dev-master-key-32-bytes"))
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return s
}

func TestDBRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemStore()
	db := NewDB(st, testSealer(t))

	if err := db.Put(ctx, "cred:acme", "sk_live_hunter2"); err != nil {
		t.Fatalf("put: %v", err)
	}
	// the stored bytes must not be the plaintext
	sealed, err := st.GetSecret(ctx, "cred:acme")
	if err != nil {
		t.Fatalf("get sealed: %v", err)
	}
	if string(sealed) == "sk_live_hunter2" {
		t.Fatal("secret stored in plaintext")
	}

	got, err := db.Get(ctx, "cred:acme")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != "sk_live_hunter2" {
		t.Fatalf("round-trip mismatch: got %q", got)
	}
}

func TestDBGetTamperedFails(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemStore()
	db := NewDB(st, testSealer(t))

	if err := db.Put(ctx, "cred:acme", "sk_live_hunter2"); err != nil {
		t.Fatalf("put: %v", err)
	}
	sealed, err := st.GetSecret(ctx, "cred:acme")
	if err != nil {
		t.Fatalf("get sealed: %v", err)
	}
	sealed[len(sealed)-1] ^= 0xFF // flip a tag byte
	if err := st.PutSecret(ctx, "cred:acme", sealed); err != nil {
		t.Fatalf("put tampered: %v", err)
	}
	if _, err := db.Get(ctx, "cred:acme"); err == nil {
		t.Fatal("expected Get of a tampered secret to fail")
	}
}

func TestDBGetMissingRefFails(t *testing.T) {
	ctx := context.Background()
	db := NewDB(store.NewMemStore(), testSealer(t))
	if _, err := db.Get(ctx, "cred:missing"); err == nil {
		t.Fatal("expected Get of missing ref to fail")
	}
}

func TestDBDeleteRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := NewDB(store.NewMemStore(), testSealer(t))

	if err := db.Put(ctx, "cred:acme", "sk_live_hunter2"); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := db.Get(ctx, "cred:acme"); err != nil {
		t.Fatalf("get before delete: %v", err)
	}
	if err := db.Delete(ctx, "cred:acme"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := db.Get(ctx, "cred:acme"); err == nil {
		t.Fatal("expected Get after delete to fail")
	}
	// deleting a nonexistent ref is a no-op.
	if err := db.Delete(ctx, "cred:acme"); err != nil {
		t.Fatalf("delete missing should be nil, got %v", err)
	}
}
