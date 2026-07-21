package rootkeys

import (
	"context"
	"testing"

	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/store"
	core "delegent.dev/protocol"
)

func newRK(t *testing.T) (*Store, *store.MemStore) {
	t.Helper()
	st := store.NewMemStore()
	sealer, err := keyring.NewAESSealer([]byte("delegent-dev-master-key-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	return New(st, sealer), st
}

func seed(t *testing.T, st *store.MemStore, id string) {
	t.Helper()
	if err := st.PutUser(context.Background(), &store.User{ID: id}); err != nil {
		t.Fatal(err)
	}
}

func TestEnsure_Idempotent(t *testing.T) {
	rk, st := newRK(t)
	ctx := context.Background()
	seed(t, st, "root:alice")

	pub1, err := rk.Ensure(ctx, "root:alice")
	if err != nil || pub1 == "" {
		t.Fatalf("first ensure: pub=%q err=%v", pub1, err)
	}
	pub2, err := rk.Ensure(ctx, "root:alice")
	if err != nil {
		t.Fatal(err)
	}
	if pub1 != pub2 {
		t.Fatalf("ensure rotated the key: %s -> %s", pub1, pub2)
	}
	// the stored key matches what Ensure returned
	u, _ := st.GetUser(ctx, "root:alice")
	if u.Pubkey != pub1 || len(u.SealedKey) == 0 {
		t.Fatalf("user key not persisted: %+v", u)
	}
}

func TestEnsure_PerPrincipalDistinctKeys(t *testing.T) {
	rk, st := newRK(t)
	ctx := context.Background()
	seed(t, st, "root:alice")
	seed(t, st, "root:bob")

	a, _ := rk.Ensure(ctx, "root:alice")
	b, _ := rk.Ensure(ctx, "root:bob")
	if a == b {
		t.Fatal("two principals must not share a root key")
	}
}

func TestSignerAndPublicAgree(t *testing.T) {
	rk, st := newRK(t)
	ctx := context.Background()
	seed(t, st, "root:alice")
	pub, _ := rk.Ensure(ctx, "root:alice")

	sg, err := rk.Signer("root:alice")
	if err != nil {
		t.Fatal(err)
	}
	if sg.Public() != pub {
		t.Fatalf("signer public %s != stored public %s", sg.Public(), pub)
	}
	// a signature from Signer verifies under the key Public reports
	msg := []byte("delegent")
	sig, _ := sg.Sign(msg)
	gotPub, ok := rk.Public("root:alice")
	if !ok || !core.VerifyBytes(gotPub, msg, sig) {
		t.Fatal("signature did not verify under the principal's public key")
	}
}

func TestSigner_MissingKeyFails(t *testing.T) {
	rk, st := newRK(t)
	seed(t, st, "root:alice") // seeded but never Ensure'd → no key
	if _, err := rk.Signer("root:alice"); err == nil {
		t.Fatal("want error signing for a principal with no root key")
	}
}
