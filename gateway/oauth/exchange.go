package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ExchangeInput carries everything the authorization_code grant needs to obtain the initial
// TokenSet: the vendor's token endpoint, our client_id (and client_secret for confidential
// clients), the authorization code the browser returned, the PKCE code_verifier that proves
// possession, and the redirect_uri that must match the one used at authorize time.
type ExchangeInput struct {
	TokenEndpoint, ClientID, ClientSecret, Code, CodeVerifier, RedirectURI string
	Now                                                                    func() int64
	HTTP                                                                   *http.Client
}

// ExchangeCode performs the OAuth2 authorization_code grant (with PKCE) and returns the initial
// TokenSet. It POSTs a form-encoded request to TokenEndpoint and parses the token response
// exactly like Refresh does (ExpiresAt = Now()+expires_in when positive; Scopes = fields of
// scope). Non-200 responses surface the status and body as an error.
func ExchangeCode(ctx context.Context, in ExchangeInput) (TokenSet, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {in.Code},
		"code_verifier": {in.CodeVerifier},
		"redirect_uri":  {in.RedirectURI},
		"client_id":     {in.ClientID},
	}
	if in.ClientSecret != "" {
		form.Set("client_secret", in.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", in.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenSet{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := in.HTTP.Do(req)
	if err != nil {
		return TokenSet{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return TokenSet{}, fmt.Errorf("code exchange failed: %d %s", resp.StatusCode, body)
	}
	// No fallback refresh token on the initial exchange — take whatever the server returns.
	return parseTokenResponse(body, in.Now, "")
}

// parseTokenResponse decodes a standard OAuth2 token endpoint JSON body into a TokenSet, shared by
// ExchangeCode and Refresh. fallbackRefresh is used when the server omits a refresh_token (a
// non-rotating server preserving the one we already hold); pass "" when there is none.
func parseTokenResponse(body []byte, now func() int64, fallbackRefresh string) (TokenSet, error) {
	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return TokenSet{}, err
	}
	// A 200 with no access_token must not silently disable auth: fail loudly so both
	// ExchangeCode and Refresh surface it instead of producing a TokenSet{AccessToken:""}.
	if raw.AccessToken == "" {
		return TokenSet{}, fmt.Errorf("token response missing access_token")
	}
	rt := raw.RefreshToken
	if rt == "" {
		rt = fallbackRefresh
	}
	ts := TokenSet{AccessToken: raw.AccessToken, RefreshToken: rt, TokenType: raw.TokenType}
	if raw.ExpiresIn > 0 {
		ts.ExpiresAt = now() + raw.ExpiresIn
	}
	if raw.Scope != "" {
		ts.Scopes = strings.Fields(raw.Scope)
	}
	return ts, nil
}
