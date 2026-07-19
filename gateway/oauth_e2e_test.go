package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"delegent.dev/gateway/oauth"
)

// TestE2E_OAuthInjectionRefresh is the gateway half of the capstone OAuth flow. The API half
// (internal/api.TestE2E_OAuthFullFlow_APIFlow) proves register → start → callback seals a live
// TokenSet under "cred:v"; this half proves the gateway CONSUMES that exact sealed blob to inject a
// Bearer token and rotates it on expiry.
//
// The two halves share one contract: the sealed TokenSet JSON under "cred:<id>". Here we seed the
// EXACT shape the callback produces — AccessToken "vendor-access-1", RefreshToken "vendor-refresh-1",
// ExpiresAt = clock + expires_in — so that seeding this by hand is equivalent to having run the API
// callback first. newOAuthSource is unexported, so this step must live in the gateway package;
// seeding the shared blob is what makes the split still prove the full end-to-end chain.
func TestE2E_OAuthInjectionRefresh(t *testing.T) {
	ctx := context.Background()
	secrets := testSecrets(t)

	// The clock the whole flow runs on. The token was minted at issue-time and expires in 3600s.
	const issued = int64(1_000_000)
	var clock atomic.Int64
	clock.Store(issued)
	now := func() int64 { return clock.Load() }

	// Seed the SAME sealed TokenSet the API callback produces under cred:v.
	seedToken(t, secrets, "cred:v", oauth.TokenSet{
		AccessToken:  "vendor-access-1",
		RefreshToken: "vendor-refresh-1",
		ExpiresAt:    issued + 3600,
		TokenType:    "Bearer",
	})

	// Fake vendor serving both grant types; the gateway half only drives refresh_token.
	var authCodeHits, refreshHits int32
	vendorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			atomic.AddInt32(&authCodeHits, 1)
			_, _ = w.Write([]byte(`{"access_token":"vendor-access-1","refresh_token":"vendor-refresh-1","expires_in":3600,"token_type":"Bearer"}`))
		case "refresh_token":
			atomic.AddInt32(&refreshHits, 1)
			if r.Form.Get("refresh_token") != "vendor-refresh-1" {
				t.Errorf("refresh sent wrong refresh_token: %q", r.Form.Get("refresh_token"))
			}
			_, _ = w.Write([]byte(`{"access_token":"vendor-access-2","refresh_token":"vendor-refresh-2","expires_in":3600}`))
		default:
			t.Errorf("unexpected grant_type: %q", r.Form.Get("grant_type"))
			http.Error(w, "bad grant", http.StatusBadRequest)
		}
	}))
	defer vendorSrv.Close()

	// Build the gateway's refreshing CredentialSource pointing at the SAME store/sealer/ref.
	src := newOAuthSource(oauthSourceCfg{
		ref:     "cred:v",
		secrets: secrets,
		client: oauth.RefreshInput{
			TokenEndpoint: vendorSrv.URL + "/token",
			ClientID:      "cid",
			ClientSecret:  "csec",
			HTTP:          vendorSrv.Client(),
		},
		now:  now,
		skew: 60,
	})

	// First injection: token is far from expiry → return the sealed access token, NO refresh.
	tok, err := src.Bearer(ctx)
	if err != nil {
		t.Fatalf("first Bearer: %v", err)
	}
	if tok != "vendor-access-1" {
		t.Fatalf("first Bearer: want vendor-access-1, got %q", tok)
	}
	if n := atomic.LoadInt32(&refreshHits); n != 0 {
		t.Fatalf("no refresh expected while token is live, got %d", n)
	}

	// Advance the clock past expiry → next injection triggers exactly ONE refresh and re-seals.
	clock.Store(issued + 3600) // now+skew >= ExpiresAt → NeedsRefresh
	tok, err = src.Bearer(ctx)
	if err != nil {
		t.Fatalf("second Bearer: %v", err)
	}
	if tok != "vendor-access-2" {
		t.Fatalf("second Bearer: want vendor-access-2 (rotated), got %q", tok)
	}
	if n := atomic.LoadInt32(&refreshHits); n != 1 {
		t.Fatalf("want exactly 1 refresh, got %d", n)
	}
	if n := atomic.LoadInt32(&authCodeHits); n != 0 {
		t.Fatalf("gateway must never run authorization_code, got %d", n)
	}

	// The rotated TokenSet is re-sealed under the same ref — the next process restart consumes it.
	raw, err := secrets.Get(ctx, "cred:v")
	if err != nil {
		t.Fatalf("get resealed: %v", err)
	}
	got, err := oauth.UnmarshalSealed(raw)
	if err != nil {
		t.Fatalf("unseal resealed: %v", err)
	}
	if got.AccessToken != "vendor-access-2" || got.RefreshToken != "vendor-refresh-2" {
		t.Fatalf("resealed token not rotated: %+v", got)
	}
}
