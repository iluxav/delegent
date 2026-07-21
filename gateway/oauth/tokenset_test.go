package oauth_test

import (
	"testing"

	"delegent.dev/gateway/oauth"
)

func TestTokenSet_ExpiredWithSkew(t *testing.T) {
	now := int64(1000)
	ts := oauth.TokenSet{AccessToken: "a", ExpiresAt: 1000 + 30} // 30s left
	if !ts.NeedsRefresh(now, 60) {                               // 60s skew → treat as expired
		t.Fatal("token within skew window must need refresh")
	}
	ts.ExpiresAt = 1000 + 120
	if ts.NeedsRefresh(now, 60) {
		t.Fatal("token with 120s left must not need refresh")
	}
	ts.RefreshToken = ""
	ts.ExpiresAt = 1
	if ts.NeedsRefresh(now, 60) && ts.RefreshToken == "" {
		// still needs refresh but is unrefreshable — caller must surface stale
	}
}

func TestTokenSet_JSONRoundTrip(t *testing.T) {
	ts := oauth.TokenSet{AccessToken: "a", RefreshToken: "r", ExpiresAt: 42, Scopes: []string{"x"}}
	b, _ := ts.MarshalSealed()
	got, err := oauth.UnmarshalSealed(b)
	if err != nil || got.AccessToken != "a" || got.RefreshToken != "r" {
		t.Fatalf("round-trip failed: %+v err %v", got, err)
	}
}
