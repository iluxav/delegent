package gateway

import (
	"context"
	"net/http/httptest"
	"reflect"
	"testing"

	"delegent.dev/gateway/agentkey"
	"delegent.dev/gateway/store"
)

// A scope the operator toggled off (Entitlement.Disabled) must be invisible to enforcement:
// neither the control-plane ceiling loaded by loadConfig nor the per-request TokenInfo minted
// by makeVerifier may carry it.

func seedDisabledEntitlement(t *testing.T, st *store.MemStore) *store.Target {
	t.Helper()
	ctx := context.Background()
	doc := `{"vendor":"gh","version":"1.0.0","classify":[],"default":{"effect":"unknown"}}`
	if err := st.PutAdapter(ctx, &store.AdapterDoc{ID: "gh", Name: "gh", Doc: []byte(doc)}); err != nil {
		t.Fatalf("put adapter: %v", err)
	}
	if err := st.PutTarget(ctx, &store.Target{ID: "gh", Name: "gh", Kind: "mcp", Endpoint: "http://gh/mcp", AdapterID: "gh", Owner: "usr_op", Enabled: true}); err != nil {
		t.Fatalf("put target: %v", err)
	}
	if err := st.PutEntitlement(ctx, &store.Entitlement{
		UserID: "usr_op", TargetID: "gh",
		Scopes:   []string{"files:read", "files:write", "mcp:connect"},
		Disabled: []string{"files:write"},
	}); err != nil {
		t.Fatalf("put entitlement: %v", err)
	}
	target, _ := st.GetTarget(ctx, "gh")
	return target
}

func TestLoadConfig_ExcludesDisabledScopes(t *testing.T) {
	st := store.NewMemStore()
	target := seedDisabledEntitlement(t, st)

	_, _, principals, _, err := loadConfig(context.Background(), st, target)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	want := []string{"files:read", "mcp:connect"}
	if !reflect.DeepEqual(principals["usr_op"], want) {
		t.Fatalf("principals[usr_op] = %v, want %v (files:write is toggled off)", principals["usr_op"], want)
	}
}

func TestMakeVerifier_ExcludesDisabledScopes(t *testing.T) {
	st := store.NewMemStore()
	seedDisabledEntitlement(t, st)
	ctx := context.Background()

	const token = "dgk_test_token"
	if err := st.PutAgentKey(ctx, &store.AgentKey{
		ID: "akey_1", UserID: "usr_op", Hash: agentkey.Hash(token), Prefix: "dgk_test", Name: "t",
	}); err != nil {
		t.Fatalf("put key: %v", err)
	}

	verify := makeVerifier(st, "gh")
	info, err := verify(ctx, token, httptest.NewRequest("POST", "/mcp/gh", nil))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	want := []string{"files:read", "mcp:connect"}
	if !reflect.DeepEqual(info.Scopes, want) {
		t.Fatalf("TokenInfo.Scopes = %v, want %v (files:write is toggled off)", info.Scopes, want)
	}
}
