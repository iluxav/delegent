package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
)

// CodeChallengeS256 returns the PKCE S256 code challenge for a verifier:
// base64url(sha256(verifier)) with no padding (RFC 7636 §4.2).
func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NewCodeVerifier builds a PKCE code verifier from caller-supplied randomness
// (base64url, no padding). Callers pass 32 crypto/rand bytes; randomness is an
// argument so the result is deterministic and testable.
func NewCodeVerifier(randBytes []byte) string {
	return base64.RawURLEncoding.EncodeToString(randBytes)
}

// AuthorizeInput holds the parameters for building an OAuth2 authorization URL.
type AuthorizeInput struct {
	AuthEndpoint  string
	ClientID      string
	RedirectURI   string
	Scopes        []string
	State         string
	CodeChallenge string
	Resource      string // RFC 8707 resource indicator; omitted if empty
}

// AuthorizeURL builds the authorization-code + PKCE authorization URL. It
// preserves any pre-existing query on the auth endpoint, sets the standard PKCE
// params (S256), and includes the RFC 8707 resource indicator when non-empty.
func AuthorizeURL(in AuthorizeInput) string {
	u, err := url.Parse(in.AuthEndpoint)
	if err != nil {
		return in.AuthEndpoint
	}
	v := u.Query()
	v.Set("response_type", "code")
	v.Set("client_id", in.ClientID)
	v.Set("redirect_uri", in.RedirectURI)
	v.Set("state", in.State)
	v.Set("code_challenge", in.CodeChallenge)
	v.Set("code_challenge_method", "S256")
	if len(in.Scopes) > 0 {
		v.Set("scope", strings.Join(in.Scopes, " "))
	}
	if in.Resource != "" {
		v.Set("resource", in.Resource)
	}
	u.RawQuery = v.Encode()
	return u.String()
}
