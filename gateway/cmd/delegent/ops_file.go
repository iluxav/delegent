package main

import (
	"context"
	"errors"
	"fmt"

	"delegent.dev/gateway"
	"delegent.dev/gateway/agentkey"
	"delegent.dev/gateway/id"
	"delegent.dev/gateway/introspect"
	"delegent.dev/gateway/oauth"
	"delegent.dev/gateway/provision"
	"delegent.dev/gateway/secretstore"
	"delegent.dev/gateway/store"
)

// fileOps edits the JSON-file store directly — used ONLY when no gateway process is running
// (then this process is the safe single writer). Consent operations need a live process and
// return errOffline; everything else mirrors the admin handlers against the same cores.
type fileOps struct {
	e *env
}

func newFileOps(e *env) *fileOps { return &fileOps{e: e} }

func (f *fileOps) Mode() string { return "offline" }
func (f *fileOps) Close() error { return f.e.st.Close() }

func (f *fileOps) targetRowFor(ctx context.Context, t *store.Target) targetRow {
	row := targetRow{ID: t.ID, Name: t.Name, Kind: t.Kind, Endpoint: t.Endpoint, Enabled: t.Enabled, CredentialKind: t.CredentialKind}
	if t.CredentialRef == "" {
		row.CredentialKind = "none"
	}
	if ad, err := f.e.st.GetAdapter(ctx, t.AdapterID); err == nil {
		if tools, err := provision.ParseAdapterTools(ad.Doc); err == nil {
			row.Tools = len(tools)
		}
	}
	return row
}

func (f *fileOps) ListTargets(ctx context.Context) ([]targetRow, error) {
	ts, err := f.e.st.ListTargets(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]targetRow, 0, len(ts))
	for _, t := range ts {
		rows = append(rows, f.targetRowFor(ctx, t))
	}
	return rows, nil
}

func (f *fileOps) TargetDetail(ctx context.Context, targetID string) (*targetDetail, error) {
	t, err := f.e.st.GetTarget(ctx, targetID)
	if err != nil {
		return nil, err
	}
	out := &targetDetail{Target: f.targetRowFor(ctx, t)}
	if ad, err := f.e.st.GetAdapter(ctx, t.AdapterID); err == nil {
		out.Tools, _ = provision.ParseAdapterTools(ad.Doc)
	}
	if t.AdvisorID != "" {
		if av, err := f.e.st.GetAdvisor(ctx, t.AdvisorID); err == nil {
			out.ScopeDocs, _ = provision.ParseAdvisorScopes(av.Doc)
		}
	}
	if ent, err := f.e.st.GetEntitlement(ctx, f.e.operator, t.ID); err == nil {
		out.Entitlement = entitlementView{Scopes: ent.Scopes, Disabled: ent.Disabled, Effective: ent.Effective()}
	}
	return out, nil
}

func (f *fileOps) PutPolicy(ctx context.Context, targetID, name string, tools []provision.ToolSpec) error {
	_, err := provision.UpdatePolicy(ctx, f.e.st, targetID, name, tools)
	return err
}

func (f *fileOps) SetTargetEnabled(ctx context.Context, targetID string, enabled bool) error {
	t, err := f.e.st.GetTarget(ctx, targetID)
	if err != nil {
		return err
	}
	t.Enabled = enabled
	return f.e.st.PutTarget(ctx, t)
}

func (f *fileOps) Introspect(ctx context.Context, targetID string) (*introspect.Result, error) {
	t, err := f.e.st.GetTarget(ctx, targetID)
	if err != nil {
		return nil, err
	}
	cred := ""
	if t.CredentialRef != "" {
		raw, err := secretstore.NewDB(f.e.st, f.e.sealer).Get(ctx, t.CredentialRef)
		if err != nil {
			return nil, fmt.Errorf("credential unavailable: %w", err)
		}
		cred = raw
		if t.CredentialKind == "oauth2" {
			if ts, err := oauth.UnmarshalSealed(raw); err == nil {
				cred = ts.AccessToken
			}
		}
	}
	return introspect.Introspect(ctx, t.Endpoint, cred)
}

func (f *fileOps) SetDisabled(ctx context.Context, targetID string, disabled []string) (*entitlementView, error) {
	ent, err := f.e.st.GetEntitlement(ctx, f.e.operator, targetID)
	if err != nil {
		return nil, err
	}
	held := map[string]bool{}
	for _, sc := range ent.Scopes {
		held[sc] = true
	}
	clamped := disabled[:0:0]
	for _, sc := range disabled {
		if held[sc] {
			clamped = append(clamped, sc)
		}
	}
	before := ent.Disabled
	ent.Disabled = clamped
	if err := f.e.st.PutEntitlement(ctx, ent); err != nil {
		return nil, err
	}
	emitScopeToggleEvents(ctx, f.e.st, f.e.operator, targetID, before, clamped)
	return &entitlementView{Scopes: ent.Scopes, Disabled: ent.Disabled, Effective: ent.Effective()}, nil
}

func (f *fileOps) ListKeys(ctx context.Context) ([]keyRow, error) {
	keys, err := f.e.st.ListAgentKeys(ctx, f.e.operator)
	if err != nil {
		return nil, err
	}
	rows := make([]keyRow, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, keyRow{ID: k.ID, Prefix: k.Prefix, Name: k.Name, CreatedAt: k.CreatedAt,
			LastUsedAt: k.LastUsedAt, RevokedAt: k.RevokedAt, ConsentChannels: k.ConsentChannels})
	}
	return rows, nil
}

func (f *fileOps) SetKeyChannels(ctx context.Context, keyID string, channels []string) error {
	if err := validateChannels(channels); err != nil {
		return err
	}
	return f.e.st.SetAgentKeyConsentChannels(ctx, keyID, channels)
}

func (f *fileOps) MintKey(ctx context.Context, name string) (keyRow, string, error) {
	full, hash, prefix := agentkey.New()
	k := &store.AgentKey{ID: id.New("akey"), UserID: f.e.operator, Hash: hash, Prefix: prefix, Name: name, CreatedAt: nowMillis()}
	if err := f.e.st.PutAgentKey(ctx, k); err != nil {
		return keyRow{}, "", err
	}
	return keyRow{ID: k.ID, Prefix: k.Prefix, Name: k.Name, CreatedAt: k.CreatedAt}, full, nil
}

func (f *fileOps) RevokeKey(ctx context.Context, keyID string) error {
	return f.e.st.RevokeAgentKey(ctx, keyID, nowMillis())
}

func (f *fileOps) RollKey(ctx context.Context, keyID string) (keyRow, string, error) {
	old, err := f.e.st.GetAgentKey(ctx, keyID)
	if err != nil {
		return keyRow{}, "", err
	}
	if old.RevokedAt != 0 {
		return keyRow{}, "", errors.New("key is already revoked — mint a new one instead")
	}
	row, plaintext, err := f.MintKey(ctx, old.Name)
	if err != nil {
		return keyRow{}, "", err
	}
	if err := f.e.st.RevokeAgentKey(ctx, old.ID, nowMillis()); err != nil {
		return row, plaintext, fmt.Errorf("new key minted (%s) but revoking the old failed: %w", row.ID, err)
	}
	return row, plaintext, nil
}

func (f *fileOps) ListEvents(ctx context.Context, filter store.EventFilter) ([]*store.Event, error) {
	filter.UserID = f.e.operator
	return f.e.st.ListEvents(ctx, filter)
}

// Consents in file mode is a read-only view of durable parked rows — there is no live
// gateway to bind a grant to, so resolution is offline-refused.
func (f *fileOps) Consents(ctx context.Context) (*consentBundle, error) {
	parked, err := f.e.st.ListConsentRequests(ctx, f.e.operator, false)
	if err != nil {
		return nil, err
	}
	return &consentBundle{Parked: parked}, nil
}

func (f *fileOps) Resolve(context.Context, string, bool, []string, int, float64) (bool, error) {
	return false, errOffline
}

func (f *fileOps) StreamConsents(context.Context) (<-chan gateway.ConsentEvent, func(), error) {
	return nil, nil, errOffline
}
