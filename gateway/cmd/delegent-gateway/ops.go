package main

// ops is the dashboard's only door to gateway state. Two implementations: apiOps (client of
// a live process's /admin surface — full features including the consent stream) and fileOps
// (direct store access — chosen only when nothing is running, so it is the safe single
// writer; no live consent features). The dashboard never touches store or registry directly.

import (
	"context"
	"errors"

	"delegent.dev/gateway"
	"delegent.dev/gateway/introspect"
	"delegent.dev/gateway/provision"
	"delegent.dev/gateway/store"
)

// errOffline marks operations that need a live gateway process.
var errOffline = errors.New("needs a running gateway (serve or stdio)")

type consentBundle struct {
	Live   []gateway.PendingView   `json:"live"`
	Parked []*store.ConsentRequest `json:"parked"`
}

type ops interface {
	// Mode is the status-line label: "live: stdio pid 4711" or "offline".
	Mode() string

	ListTargets(ctx context.Context) ([]targetRow, error)
	TargetDetail(ctx context.Context, id string) (*targetDetail, error)
	PutPolicy(ctx context.Context, id, name string, tools []provision.ToolSpec) error
	SetTargetEnabled(ctx context.Context, id string, enabled bool) error
	Introspect(ctx context.Context, id string) (*introspect.Result, error)

	// SetDisabled replaces the operator's opt-out list on one target's entitlement.
	SetDisabled(ctx context.Context, targetID string, disabled []string) (*entitlementView, error)

	ListKeys(ctx context.Context) ([]keyRow, error)
	MintKey(ctx context.Context, name string) (keyRow, string, error)
	RevokeKey(ctx context.Context, id string) error
	RollKey(ctx context.Context, id string) (keyRow, string, error)

	ListEvents(ctx context.Context, f store.EventFilter) ([]*store.Event, error)

	Consents(ctx context.Context) (*consentBundle, error)
	// Resolve approves (with a scope subset, TTL, budget) or denies a pending ask.
	// ok=false: no live ask held that id. errOffline in file mode.
	Resolve(ctx context.Context, id string, approve bool, scopes []string, ttlMinutes int, budgetUSD float64) (bool, error)
	// StreamConsents delivers park/resolve deltas until cancel. errOffline in file mode.
	StreamConsents(ctx context.Context) (<-chan gateway.ConsentEvent, func(), error)

	Close() error
}
