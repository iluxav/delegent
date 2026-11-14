package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"delegent.dev/gateway/a2a"
	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/origin"
	"delegent.dev/gateway/secretstore"
	"delegent.dev/gateway/store"
)

// headerSpy is a fake HTTP server that remembers whether it was called and the Authorization
// header of the last request it received.
type headerSpy struct {
	*httptest.Server
	hits atomic.Int32
	auth atomic.Value
}

// newHeaderSpy starts a server that records each request and then hands it to respond.
func newHeaderSpy(t *testing.T, respond http.HandlerFunc) *headerSpy {
	t.Helper()
	s := &headerSpy{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.auth.Store(r.Header.Get("Authorization"))
		respond(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *headerSpy) lastAuth() string {
	a, _ := s.auth.Load().(string)
	return a
}

// TestNew_CredentialStaysOnTargetOrigin drives the real upstream client (the MCP SDK's
// streamable transport, as New wires it) at a vendor that answers with a redirect to another
// host. The vendor's credential must reach the vendor and must not reach the other host.
//
// http.Client removes Authorization when a redirect leaves the host, but the credential is
// attached by a RoundTripper, which also carries the redirected request. Unless the transport
// checks where a request is going, it puts the credential back.
func TestNew_CredentialStaysOnTargetOrigin(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemStore()
	sealer, err := keyring.NewAESSealer([]byte("delegent-dev-master-key-32-bytes"))
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	if err := secretstore.NewDB(st, sealer).Put(ctx, "cred:v", "VENDOR-SECRET"); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	// Neither server speaks MCP, so New fails at connect. The headers are recorded before that.
	other := newHeaderSpy(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	vendor := newHeaderSpy(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/mcp", http.StatusTemporaryRedirect)
	})

	if err := st.PutAdapter(ctx, &store.AdapterDoc{ID: "a", Name: "a", Doc: []byte(`{}`)}); err != nil {
		t.Fatalf("put adapter: %v", err)
	}
	target := &store.Target{
		ID: "v", Name: "V", Kind: "mcp", Endpoint: vendor.URL + "/mcp",
		AdapterID: "a", Owner: "usr_op", Enabled: true,
		CredentialKind: "static_bearer", CredentialRef: "cred:v",
	}
	if err := st.PutTarget(ctx, target); err != nil {
		t.Fatalf("put target: %v", err)
	}
	if err := st.PutEntitlement(ctx, &store.Entitlement{UserID: "usr_op", TargetID: "v", Scopes: []string{"files:read"}}); err != nil {
		t.Fatalf("put entitlement: %v", err)
	}

	if g, _ := New(ctx, st, sealer, target); g != nil {
		g.Close()
	}

	if got := vendor.lastAuth(); got != "Bearer VENDOR-SECRET" {
		t.Fatalf("the vendor did not receive its credential: got %q", got)
	}
	if other.hits.Load() == 0 {
		t.Fatal("the redirect was not followed, so this test shows nothing about the other host")
	}
	if got := other.lastAuth(); got != "" {
		t.Fatalf("the vendor's credential was sent to the host it redirected to: %q", got)
	}
}

// A redirect to another path on the target's own origin still carries the credential.
func TestAuthTransport_SameOriginRedirectKeepsCredential(t *testing.T) {
	vendor := newHeaderSpy(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", http.StatusTemporaryRedirect)
		}
	})
	client := &http.Client{Transport: &authTransport{
		src: staticSource{cred: "VENDOR-SECRET"}, base: http.DefaultTransport, to: origin.Of(vendor.URL),
	}}
	res, err := client.Post(vendor.URL+"/old", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	res.Body.Close()

	if got := res.Request.URL.Path; got != "/new" {
		t.Fatalf("the redirect was not followed: ended at %q", got)
	}
	if got := vendor.lastAuth(); got != "Bearer VENDOR-SECRET" {
		t.Fatalf("the credential was dropped on a redirect within the target's origin: got %q", got)
	}
}

// countingSource is a CredentialSource that counts how often it is asked.
type countingSource struct{ asked atomic.Int32 }

func (c *countingSource) Bearer(context.Context) (string, error) {
	c.asked.Add(1)
	return "VENDOR-SECRET", nil
}

// A request to another origin is sent without the credential, and the credential source is
// not consulted for it: an OAuth source would otherwise refresh a token for a host that will
// never receive it. A transport with no origin (the endpoint did not parse) sends it nowhere.
func TestAuthTransport_OtherOriginGetsNoCredential(t *testing.T) {
	vendor := newHeaderSpy(t, func(http.ResponseWriter, *http.Request) {})
	other := newHeaderSpy(t, func(http.ResponseWriter, *http.Request) {})

	for _, c := range []struct {
		name string
		to   origin.Origin
	}{
		{"bound to the vendor", origin.Of(vendor.URL)},
		{"bound to nothing", origin.Origin{}},
	} {
		src := &countingSource{}
		client := &http.Client{Transport: &authTransport{src: src, base: http.DefaultTransport, to: c.to}}
		res, err := client.Get(other.URL + "/mcp")
		if err != nil {
			t.Fatalf("%s: get: %v", c.name, err)
		}
		res.Body.Close()
		if got := other.lastAuth(); got != "" {
			t.Errorf("%s: the credential was sent to another origin: %q", c.name, got)
		}
		if n := src.asked.Load(); n != 0 {
			t.Errorf("%s: the credential source was asked %d time(s) for another origin", c.name, n)
		}
	}
}

// An agent target whose card names a URL on another origin is refused at connect, so the
// target's credential is never sent to the host the card chose.
func TestNewA2AUpstream_RefusesCardURLOnAnotherOrigin(t *testing.T) {
	other := newHeaderSpy(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(a2a.Card{Name: "Agent", URL: other.URL + "/rpc", Skills: []a2a.Skill{{ID: "work", Name: "Work"}}})
	}))
	defer vendor.Close()

	up, err := newA2AUpstream(context.Background(), vendor.URL, "VENDOR-SECRET")
	if err == nil {
		// Before the check existed the gateway connected, and the first call carried the
		// credential to the other host. Make that call so the failure shows what leaked.
		_, _ = up.client.Send(context.Background(), "hi", a2a.SendOpts{NoWait: true})
		t.Fatalf("connected to an agent whose card names another origin; that host saw Authorization %q", other.lastAuth())
	}
	if !errors.Is(err, a2a.ErrCardOrigin) {
		t.Errorf("err = %v, want one that wraps a2a.ErrCardOrigin", err)
	}
	if n := other.hits.Load(); n != 0 {
		t.Errorf("the host the card named received %d request(s)", n)
	}
}
