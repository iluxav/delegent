package oauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"delegent.dev/gateway/oauth"
)

func TestExchangeCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Fatalf("grant_type wrong: %v", r.Form)
		}
		if r.Form.Get("code") != "auth-code" {
			t.Fatalf("code wrong: %v", r.Form)
		}
		if r.Form.Get("code_verifier") != "verifier-xyz" {
			t.Fatalf("code_verifier wrong: %v", r.Form)
		}
		if r.Form.Get("redirect_uri") != "https://app/cb" {
			t.Fatalf("redirect_uri wrong: %v", r.Form)
		}
		if r.Form.Get("client_id") != "cid" || r.Form.Get("client_secret") != "csec" {
			t.Fatalf("client creds wrong: %v", r.Form)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Fatalf("missing Accept header: %v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"acc","refresh_token":"ref","expires_in":3600,"token_type":"Bearer","scope":"a b"}`))
	}))
	defer srv.Close()

	got, err := oauth.ExchangeCode(context.Background(), oauth.ExchangeInput{
		TokenEndpoint: srv.URL, ClientID: "cid", ClientSecret: "csec",
		Code: "auth-code", CodeVerifier: "verifier-xyz", RedirectURI: "https://app/cb",
		Now: func() int64 { return 1000 }, HTTP: srv.Client(),
	})
	if err != nil {
		t.Fatalf("exchange err: %v", err)
	}
	if got.AccessToken != "acc" || got.RefreshToken != "ref" || got.ExpiresAt != 1000+3600 {
		t.Fatalf("token set wrong: %+v", got)
	}
	if got.TokenType != "Bearer" {
		t.Fatalf("token type: %q", got.TokenType)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "a" || got.Scopes[1] != "b" {
		t.Fatalf("scopes: %v", got.Scopes)
	}
}

func TestExchangeCode_EmptyAccessTokenReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 200 OK but no access_token — must not silently produce an empty TokenSet.
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	_, err := oauth.ExchangeCode(context.Background(), oauth.ExchangeInput{
		TokenEndpoint: srv.URL, ClientID: "cid", Code: "c", CodeVerifier: "v", RedirectURI: "https://app/cb",
		Now: func() int64 { return 1000 }, HTTP: srv.Client(),
	})
	if err == nil {
		t.Fatal("expected error when access_token is missing from a 200 response")
	}
}

func TestExchangeCode_NonOKReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	_, err := oauth.ExchangeCode(context.Background(), oauth.ExchangeInput{
		TokenEndpoint: srv.URL, ClientID: "cid", Code: "c", CodeVerifier: "v", RedirectURI: "https://app/cb",
		Now: func() int64 { return 1000 }, HTTP: srv.Client(),
	})
	if err == nil {
		t.Fatal("expected error on non-200 response")
	}
}
