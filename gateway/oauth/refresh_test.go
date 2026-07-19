package oauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"delegent.dev/gateway/oauth"
)

func TestRefresh_RotatesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "old-r" {
			t.Fatalf("bad refresh form: %v", r.Form)
		}
		if r.Form.Get("client_id") != "cid" || r.Form.Get("client_secret") != "csec" {
			t.Fatalf("bad client creds in form: %v", r.Form)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Fatalf("missing Accept header: %v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-a","refresh_token":"new-r","expires_in":3600,"token_type":"Bearer","scope":"a b"}`))
	}))
	defer srv.Close()

	got, err := oauth.Refresh(context.Background(), oauth.RefreshInput{
		TokenEndpoint: srv.URL, ClientID: "cid", ClientSecret: "csec",
		RefreshToken: "old-r", Now: func() int64 { return 1000 }, HTTP: srv.Client(),
	})
	if err != nil || got.AccessToken != "new-a" || got.RefreshToken != "new-r" || got.ExpiresAt != 1000+3600 {
		t.Fatalf("refresh: %+v err %v", got, err)
	}
	if got.TokenType != "Bearer" {
		t.Fatalf("token type: %q", got.TokenType)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "a" || got.Scopes[1] != "b" {
		t.Fatalf("scopes: %v", got.Scopes)
	}
}

func TestRefresh_PreservesRefreshTokenWhenOmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		// non-rotating server: omits refresh_token in the response
		if r.Form.Get("client_secret") != "" {
			t.Fatalf("client_secret should be omitted when empty: %v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-a","expires_in":100}`))
	}))
	defer srv.Close()

	got, err := oauth.Refresh(context.Background(), oauth.RefreshInput{
		TokenEndpoint: srv.URL, ClientID: "cid",
		RefreshToken: "keep-me", Now: func() int64 { return 500 }, HTTP: srv.Client(),
	})
	if err != nil {
		t.Fatalf("refresh err: %v", err)
	}
	if got.RefreshToken != "keep-me" {
		t.Fatalf("expected preserved refresh token, got %q", got.RefreshToken)
	}
	if got.ExpiresAt != 500+100 {
		t.Fatalf("expires_at: %d", got.ExpiresAt)
	}
}

func TestRefresh_EmptyAccessTokenReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 200 OK but no access_token — must fail loudly rather than disable auth.
		_, _ = w.Write([]byte(`{"expires_in":3600}`))
	}))
	defer srv.Close()

	_, err := oauth.Refresh(context.Background(), oauth.RefreshInput{
		TokenEndpoint: srv.URL, ClientID: "cid", RefreshToken: "old-r",
		Now: func() int64 { return 1000 }, HTTP: srv.Client(),
	})
	if err == nil {
		t.Fatal("expected error when access_token is missing from a 200 response")
	}
}

func TestRefresh_NonOKReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	_, err := oauth.Refresh(context.Background(), oauth.RefreshInput{
		TokenEndpoint: srv.URL, ClientID: "cid", RefreshToken: "old-r",
		Now: func() int64 { return 1000 }, HTTP: srv.Client(),
	})
	if err == nil {
		t.Fatal("expected error on non-200 response")
	}
}
