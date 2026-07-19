package oauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// RefreshInput carries everything the refresh_token grant needs. RefreshToken is
// filled per call by the caller (e.g. oauthSource) from the current TokenSet.
type RefreshInput struct {
	TokenEndpoint, ClientID, ClientSecret, RefreshToken string
	Now                                                 func() int64
	HTTP                                                *http.Client
}

// Refresh performs the OAuth2 refresh_token grant and returns the new TokenSet.
// It preserves the old refresh token if the server omits a new one (non-rotating
// servers) and only sets ExpiresAt when the server reports a positive expires_in.
func Refresh(ctx context.Context, in RefreshInput) (TokenSet, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {in.RefreshToken},
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
		return TokenSet{}, fmt.Errorf("refresh failed: %d %s", resp.StatusCode, body)
	}
	// Fall back to the refresh token we sent when the server omits one (non-rotating server).
	return parseTokenResponse(body, in.Now, in.RefreshToken)
}
