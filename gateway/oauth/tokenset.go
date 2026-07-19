package oauth

import "encoding/json"

// TokenSet is the sealed credential payload for an OAuth2 vendor target.
type TokenSet struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	ExpiresAt    int64    `json:"expires_at"`           // unix seconds; 0 = unknown/never
	Scopes       []string `json:"scopes,omitempty"`     //
	TokenType    string   `json:"token_type,omitempty"` // usually "Bearer"
}

// NeedsRefresh reports whether the access token is at/near expiry.
func (t TokenSet) NeedsRefresh(now, skewSeconds int64) bool {
	if t.ExpiresAt == 0 {
		return false
	}
	return now+skewSeconds >= t.ExpiresAt
}

// MarshalSealed serializes the TokenSet to a JSON string for sealing.
func (t TokenSet) MarshalSealed() (string, error) { b, err := json.Marshal(t); return string(b), err }

// UnmarshalSealed parses a sealed JSON string back into a TokenSet.
func UnmarshalSealed(s string) (TokenSet, error) {
	var t TokenSet
	err := json.Unmarshal([]byte(s), &t)
	return t, err
}
