package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/oauth"
	"delegent.dev/gateway/secretstore"
	"delegent.dev/gateway/store"
)

func testSecrets(t *testing.T) secretstore.Writer {
	t.Helper()
	sealer, err := keyring.NewAESSealer([]byte("delegent-dev-master-key-32-bytes"))
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return secretstore.NewDB(store.NewMemStore(), sealer)
}

func seedToken(t *testing.T, secrets secretstore.Writer, ref string, ts oauth.TokenSet) {
	t.Helper()
	js, err := ts.MarshalSealed()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := secrets.Put(context.Background(), ref, js); err != nil {
		t.Fatalf("seed put: %v", err)
	}
}

func TestOAuthSource_RefreshesAndReseals(t *testing.T) {
	secrets := testSecrets(t)
	seedToken(t, secrets, "cred:v", oauth.TokenSet{AccessToken: "old-a", RefreshToken: "old-r", ExpiresAt: 1000})

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"access_token":"new-a","refresh_token":"new-r","expires_in":3600}`))
	}))
	defer srv.Close()

	src := newOAuthSource(oauthSourceCfg{
		ref: "cred:v", secrets: secrets,
		client: oauth.RefreshInput{TokenEndpoint: srv.URL, ClientID: "c", HTTP: srv.Client()},
		now:    func() int64 { return 1000 }, skew: 60,
	})

	// concurrent: many callers, exactly one refresh (single-flight)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := src.Bearer(context.Background())
			if err != nil || tok != "new-a" {
				t.Errorf("bearer: %q %v", tok, err)
			}
		}()
	}
	wg.Wait()

	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected 1 refresh, got %d", hits)
	}
	// persisted TokenSet is the rotated one, re-sealed
	raw, err := secrets.Get(context.Background(), "cred:v")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, err := oauth.UnmarshalSealed(raw)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if got.AccessToken != "new-a" || got.RefreshToken != "new-r" {
		t.Fatalf("token not re-sealed: %+v", got)
	}
}

func TestOAuthSource_ValidTokenNoRefresh(t *testing.T) {
	secrets := testSecrets(t)
	seedToken(t, secrets, "cred:v", oauth.TokenSet{AccessToken: "still-good", RefreshToken: "r", ExpiresAt: 5000})

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	src := newOAuthSource(oauthSourceCfg{
		ref: "cred:v", secrets: secrets,
		client: oauth.RefreshInput{TokenEndpoint: srv.URL, ClientID: "c", HTTP: srv.Client()},
		now:    func() int64 { return 1000 }, skew: 60,
	})

	tok, err := src.Bearer(context.Background())
	if err != nil || tok != "still-good" {
		t.Fatalf("bearer: %q %v", tok, err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("expected no endpoint hits, got %d", hits)
	}
}

func TestOAuthSource_EmptyAccessTokenErrors(t *testing.T) {
	secrets := testSecrets(t)
	// Corrupt/empty sealed token but not near expiry (NeedsRefresh is false) — the
	// early-return path must fail loudly rather than inject an empty bearer.
	seedToken(t, secrets, "cred:v", oauth.TokenSet{AccessToken: "", RefreshToken: "r", ExpiresAt: 5000})

	src := newOAuthSource(oauthSourceCfg{
		ref: "cred:v", secrets: secrets,
		client: oauth.RefreshInput{TokenEndpoint: "http://unused", ClientID: "c", HTTP: http.DefaultClient},
		now:    func() int64 { return 1000 }, skew: 60,
	})

	tok, err := src.Bearer(context.Background())
	if err == nil {
		t.Fatalf("expected error for empty access token, got token %q", tok)
	}
}

func TestOAuthSource_ExpiredNoRefreshTokenErrors(t *testing.T) {
	secrets := testSecrets(t)
	seedToken(t, secrets, "cred:v", oauth.TokenSet{AccessToken: "dead", RefreshToken: "", ExpiresAt: 1000})

	src := newOAuthSource(oauthSourceCfg{
		ref: "cred:v", secrets: secrets,
		client: oauth.RefreshInput{TokenEndpoint: "http://unused", ClientID: "c", HTTP: http.DefaultClient},
		now:    func() int64 { return 1000 }, skew: 60,
	})

	_, err := src.Bearer(context.Background())
	if err == nil {
		t.Fatal("expected error for expired token with no refresh token")
	}
}
