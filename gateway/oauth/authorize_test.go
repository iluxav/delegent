package oauth_test

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"delegent.dev/gateway/oauth"
)

func TestPKCE_S256(t *testing.T) {
	// RFC 7636 Appendix B test vector.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	got := oauth.CodeChallengeS256(verifier)
	if got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("S256 mismatch: %s", got)
	}
}

func TestAuthorizeURL(t *testing.T) {
	raw := oauth.AuthorizeURL(oauth.AuthorizeInput{
		AuthEndpoint:  "https://as.example/authorize",
		ClientID:      "cid",
		RedirectURI:   "https://app/cb",
		Scopes:        []string{"a", "b"},
		State:         "st",
		CodeChallenge: "cc",
		Resource:      "https://vendor/mcp",
	})
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	checks := map[string]string{
		"response_type":         "code",
		"client_id":             "cid",
		"redirect_uri":          "https://app/cb",
		"state":                 "st",
		"code_challenge":        "cc",
		"code_challenge_method": "S256",
		"scope":                 "a b",
		"resource":              "https://vendor/mcp",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Fatalf("param %q = %q, want %q", k, got, want)
		}
	}
	if u.Host != "as.example" || u.Path != "/authorize" {
		t.Fatalf("endpoint not preserved: %s", u.String())
	}
}

func TestNewCodeVerifier_RoundTrip(t *testing.T) {
	in := make([]byte, 32)
	for i := range in {
		in[i] = byte(i)
	}
	v := oauth.NewCodeVerifier(in)
	if v == "" {
		t.Fatal("empty verifier")
	}
	if strings.Contains(v, "=") {
		t.Fatalf("verifier has padding: %s", v)
	}
	got, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got) != string(in) {
		t.Fatalf("round-trip mismatch")
	}
}
