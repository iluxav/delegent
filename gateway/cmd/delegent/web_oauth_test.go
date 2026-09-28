package main

import (
	"strings"
	"testing"
)

// A server that issues refresh tokens only for offline_access (Vercel) is asked for it, so its
// token can be renewed; one that does not offer it is not.
func TestOfflineAccessIsRequestedWhenOffered(t *testing.T) {
	got := withOfflineAccess([]string{"openid"}, []string{"openid", "email", "offline_access"})
	if strings.Join(got, " ") != "openid offline_access" {
		t.Errorf("scopes = %v", got)
	}
	if got := withOfflineAccess([]string{"read"}, []string{"read", "write"}); strings.Join(got, " ") != "read" {
		t.Errorf("added a scope the server does not offer: %v", got)
	}
	if got := withOfflineAccess([]string{"offline_access"}, []string{"offline_access"}); len(got) != 1 {
		t.Errorf("asked twice: %v", got)
	}
}
