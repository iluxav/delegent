package gateway

import (
	"context"
	"fmt"
	"sync"
	"time"

	"delegent.dev/gateway/oauth"
	"delegent.dev/gateway/secretstore"
)

// oauthSourceCfg configures a refreshing CredentialSource for an OAuth2 vendor target.
type oauthSourceCfg struct {
	ref     string             // secrets ref holding the sealed TokenSet
	secrets secretstore.Writer // Get + Put (seal/unseal)
	client  oauth.RefreshInput // TokenEndpoint/ClientID/ClientSecret/HTTP (RefreshToken/Now filled per call)
	now     func() int64
	skew    int64 // seconds of leeway before expiry to trigger a refresh
}

// oauthSource unseals a TokenSet, refreshes it when near expiry, re-seals the
// (possibly rotated) result, and returns a live access token. The mutex gives
// single-flight within one gateway instance so 20 concurrent callers cause at
// most one refresh and re-seal.
type oauthSource struct {
	cfg oauthSourceCfg
	mu  sync.Mutex
}

func newOAuthSource(cfg oauthSourceCfg) *oauthSource {
	if cfg.now == nil {
		cfg.now = func() int64 { return time.Now().Unix() }
	}
	if cfg.skew == 0 {
		cfg.skew = 60
	}
	return &oauthSource{cfg: cfg}
}

// Bearer returns a live access token, refreshing and re-sealing under the lock
// if the current token is at/near expiry.
func (s *oauthSource) Bearer(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := s.cfg.secrets.Get(ctx, s.cfg.ref)
	if err != nil {
		return "", fmt.Errorf("oauth: unseal token: %w", err)
	}
	ts, err := oauth.UnmarshalSealed(raw)
	if err != nil {
		return "", fmt.Errorf("oauth: parse token: %w", err)
	}
	if !ts.NeedsRefresh(s.cfg.now(), s.cfg.skew) {
		if ts.AccessToken == "" {
			return "", fmt.Errorf("oauth: empty access token (re-consent needed)")
		}
		return ts.AccessToken, nil
	}
	if ts.RefreshToken == "" {
		return "", fmt.Errorf("oauth: token expired and no refresh token (needs re-consent)")
	}

	in := s.cfg.client
	in.RefreshToken = ts.RefreshToken
	in.Now = s.cfg.now
	next, err := oauth.Refresh(ctx, in)
	if err != nil {
		return "", fmt.Errorf("oauth: refresh: %w", err)
	}
	js, err := next.MarshalSealed()
	if err != nil {
		return "", err
	}
	if err := s.cfg.secrets.Put(ctx, s.cfg.ref, js); err != nil {
		return "", fmt.Errorf("oauth: reseal: %w", err)
	}
	if next.AccessToken == "" {
		return "", fmt.Errorf("oauth: empty access token (re-consent needed)")
	}
	return next.AccessToken, nil
}
