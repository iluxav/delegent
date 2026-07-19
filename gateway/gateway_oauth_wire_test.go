package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/oauth"
	"delegent.dev/gateway/secretstore"
	"delegent.dev/gateway/store"
)

// TestNew_OAuth2SelectsRefreshingSource proves New's credential switch selects the OAuth branch
// for a CredentialKind=="oauth2" target: it wires an *authTransport backed by an *oauthSource
// that refreshes the expiring TokenSet against the vendor token endpoint and injects the rotated
// access token as the upstream Bearer.
//
// Approach: standing up New() end-to-end needs a LIVE MCP upstream (client.Connect speaks the
// streamable protocol), which is impractical to fake in a unit test — so we assert at the seam.
// We (1) build the oauthSource exactly as the switch does and confirm Bearer() returns the
// refreshed token + re-seals, and (2) call gateway.New for the oauth2 target and confirm it
// selects the oauth branch by observing the rotated Bearer arrive at the (fake) upstream during
// the connect attempt. New returns a connect error (no real MCP server), which is expected and
// tolerated; the point is that it took the oauth path and did not panic.
func TestNew_OAuth2SelectsRefreshingSource(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemStore()
	sealer, err := keyring.NewAESSealer([]byte("delegent-dev-master-key-32-bytes"))
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	secrets := secretstore.NewDB(st, sealer)

	// Seed a sealed, expiring TokenSet under the target's CredentialRef.
	seedToken(t, secrets, "cred:v", oauth.TokenSet{AccessToken: "old-a", RefreshToken: "old-r", ExpiresAt: 1000})

	// Fake vendor token endpoint: returns a rotated token on refresh.
	var refreshHits int32
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&refreshHits, 1)
		_, _ = w.Write([]byte(`{"access_token":"new-a","refresh_token":"new-r","expires_in":3600}`))
	}))
	defer tokenSrv.Close()

	// oauth_clients row pointing at the fake token endpoint (public client — no secret ref).
	if err := st.PutOAuthClient(ctx, &store.OAuthClient{
		TargetID: "v", AuthEndpoint: "https://as.example/authorize",
		TokenEndpoint: tokenSrv.URL, ClientID: "cid", RedirectURI: "https://app/cb",
	}); err != nil {
		t.Fatalf("put oauth client: %v", err)
	}

	// (1) Seam assertion: the source the switch builds refreshes + re-seals correctly.
	src := newOAuthSource(oauthSourceCfg{
		ref:     "cred:v",
		secrets: secrets,
		client:  oauth.RefreshInput{TokenEndpoint: tokenSrv.URL, ClientID: "cid", HTTP: http.DefaultClient},
	})
	tok, err := src.Bearer(ctx)
	if err != nil || tok != "new-a" {
		t.Fatalf("refreshing source Bearer: got %q err %v (want new-a)", tok, err)
	}
	raw, err := secrets.Get(ctx, "cred:v")
	if err != nil {
		t.Fatalf("get resealed: %v", err)
	}
	resealed, err := oauth.UnmarshalSealed(raw)
	if err != nil || resealed.AccessToken != "new-a" || resealed.RefreshToken != "new-r" {
		t.Fatalf("token not re-sealed: %+v err %v", resealed, err)
	}

	// (2) New selects the oauth branch: re-seed the expiring token so New's transport must refresh
	// again, and point the target's endpoint at a fake upstream that records the injected Bearer.
	seedToken(t, secrets, "cred:v", oauth.TokenSet{AccessToken: "old-a", RefreshToken: "new-r", ExpiresAt: 1000})
	var gotAuth atomic.Value
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Header.Get("Authorization"); a != "" {
			gotAuth.Store(a)
		}
		w.WriteHeader(http.StatusBadRequest) // not a real MCP server — connect will fail after we record the header
	}))
	defer upstreamSrv.Close()

	// Minimal config so New gets past loadConfig to the credential switch and the connect attempt.
	if err := st.PutAdapter(ctx, &store.AdapterDoc{ID: "a", Name: "a", Doc: []byte(`{}`)}); err != nil {
		t.Fatalf("put adapter: %v", err)
	}
	target := &store.Target{
		ID: "v", Name: "V", Kind: "mcp", Endpoint: upstreamSrv.URL,
		AdapterID: "a", Owner: "usr_op", Enabled: true,
		CredentialKind: "oauth2", CredentialRef: "cred:v",
	}
	if err := st.PutTarget(ctx, target); err != nil {
		t.Fatalf("put target: %v", err)
	}
	if err := st.PutEntitlement(ctx, &store.Entitlement{UserID: "usr_op", TargetID: "v", Scopes: []string{"files:read"}}); err != nil {
		t.Fatalf("put entitlement: %v", err)
	}

	// New is expected to fail at the upstream connect (fake server isn't a real MCP endpoint); it
	// must not panic, and it must have taken the oauth branch — proven by the rotated Bearer
	// reaching the fake upstream.
	g, _ := New(ctx, st, sealer, target)
	if g != nil {
		g.Close()
	}
	if got, _ := gotAuth.Load().(string); got != "Bearer new-a" {
		t.Fatalf("New did not inject the refreshed OAuth bearer upstream: got %q (want %q)", got, "Bearer new-a")
	}
}
