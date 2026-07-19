// Package secretstore is the port through which the gateway fetches the REAL vendor
// credential — the only component that ever holds a vendor secret. The DB implementation
// seals the secret with the server master key (keyring.Sealer) before it touches storage and
// unseals it only at read time, so a raw credential never lands in the database. Static is a
// trivial in-memory implementation for dev and tests.
//
// The Store interface is deliberately the custody seam: implementations may later back onto
// external vaults (HashiCorp Vault, AWS Secrets Manager, a customer's own BYO vault) with zero
// call-site changes. The DB/master-key implementation is the MVP custodian.
package secretstore

import (
	"context"
	"fmt"

	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/store"
)

// Store resolves a credential reference to the real secret (e.g. "sk_live_..."). The agent
// never sees this — the gateway attaches it on the way out.
type Store interface {
	Get(ctx context.Context, ref string) (string, error)
}

// Writer is a Store that can also stash and remove a secret (used by the create-target flow).
type Writer interface {
	Store
	Put(ctx context.Context, ref, secret string) error
	// Delete removes a sealed secret. Deleting a nonexistent ref is a no-op.
	Delete(ctx context.Context, ref string) error
}

// Static is a trivial in-memory Store, for dev and tests.
type Static map[string]string

func (s Static) Get(_ context.Context, ref string) (string, error) {
	v, ok := s[ref]
	if !ok {
		return "", fmt.Errorf("no credential for ref %q", ref)
	}
	return v, nil
}

// DB seals credentials with the master key and stores the sealed bytes via store.Store.
type DB struct {
	st     store.Store
	sealer keyring.Sealer
}

// NewDB builds a sealed, database-backed secret store.
func NewDB(st store.Store, sealer keyring.Sealer) *DB {
	return &DB{st: st, sealer: sealer}
}

func (d *DB) Get(ctx context.Context, ref string) (string, error) {
	sealed, err := d.st.GetSecret(ctx, ref)
	if err != nil {
		return "", err
	}
	plain, err := d.sealer.Unseal(sealed)
	if err != nil {
		return "", fmt.Errorf("unseal secret %q: %w", ref, err)
	}
	return string(plain), nil
}

func (d *DB) Put(ctx context.Context, ref, secret string) error {
	sealed, err := d.sealer.Seal([]byte(secret))
	if err != nil {
		return err
	}
	return d.st.PutSecret(ctx, ref, sealed)
}

// Delete removes a sealed secret. Deleting a nonexistent ref is a no-op.
func (d *DB) Delete(ctx context.Context, ref string) error {
	return d.st.DeleteSecret(ctx, ref)
}
