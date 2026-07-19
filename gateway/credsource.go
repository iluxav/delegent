package gateway

import "context"

// CredentialSource yields the bearer token to inject on each upstream request.
// Implementations may refresh under the hood; RoundTrip calls this per request.
type CredentialSource interface {
	Bearer(ctx context.Context) (string, error)
}

type staticSource struct{ cred string }

func (s staticSource) Bearer(context.Context) (string, error) { return s.cred, nil }
