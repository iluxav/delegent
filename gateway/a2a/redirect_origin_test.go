package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// spyServer records how many requests it received and the Authorization and session headers
// of the last one.
type spyServer struct {
	*httptest.Server
	hits    atomic.Int32
	auth    atomic.Value
	session atomic.Value
}

func newSpyServer(t *testing.T, respond http.HandlerFunc) *spyServer {
	t.Helper()
	s := &spyServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.auth.Store(r.Header.Get("Authorization"))
		s.session.Store(r.Header.Get(SessionHeader))
		respond(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *spyServer) last() (auth, session string) {
	auth, _ = s.auth.Load().(string)
	session, _ = s.session.Load().(string)
	return auth, session
}

// rpcOK answers any JSON-RPC call with a completed message.
func rpcOK(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"kind":"message","role":"agent","messageId":"m1","parts":[{"kind":"text","text":"done"}]}}`)
}

// An agent that answers a call with a redirect to another origin does not get the call, the
// credential or the caller's session handle delivered there.
//
// Go removes Authorization on a redirect to an unrelated host, but keeps it for another port
// on the same host and for a subdomain. The second server here is another port on 127.0.0.1,
// which is the case Go lets through.
func TestClient_RefusesRedirectToAnotherOrigin(t *testing.T) {
	other := newSpyServer(t, rpcOK)
	vendor := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/rpc", http.StatusTemporaryRedirect)
	})

	c := &Client{URL: vendor.URL + "/rpc", Credential: "VENDOR-SECRET"}
	_, err := c.Send(context.Background(), "hi", SendOpts{Session: "ses_caller", NoWait: true})

	if n := other.hits.Load(); n != 0 {
		auth, session := other.last()
		t.Errorf("the other origin received %d request(s), with Authorization %q and session %q", n, auth, session)
	}
	if !errors.Is(err, ErrRedirectOrigin) {
		t.Errorf("Send error = %v, want one that wraps ErrRedirectOrigin", err)
	}
	if auth, _ := vendor.last(); auth != "Bearer VENDOR-SECRET" {
		t.Errorf("the agent did not receive its credential: got %q", auth)
	}
}

// The same for the card: an endpoint that redirects the card request to another origin does
// not get the credential delivered there.
func TestFetchCard_RefusesRedirectToAnotherOrigin(t *testing.T) {
	other := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Card{Name: "Agent", Skills: []Skill{{ID: "work", Name: "Work"}}})
	})
	vendor := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+WellKnownPath, http.StatusFound)
	})

	_, err := FetchCard(context.Background(), vendor.URL, "VENDOR-SECRET")

	if n := other.hits.Load(); n != 0 {
		auth, _ := other.last()
		t.Errorf("the other origin received %d request(s), with Authorization %q", n, auth)
	}
	if !errors.Is(err, ErrRedirectOrigin) {
		t.Errorf("FetchCard error = %v, want one that wraps ErrRedirectOrigin", err)
	}
}

// A redirect within the agent's own origin is still followed, for calls and for the card.
func TestRedirectWithinTheOriginIsFollowed(t *testing.T) {
	vendor := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rpc":
			http.Redirect(w, r, "/v2/rpc", http.StatusTemporaryRedirect)
		case "/v2/rpc":
			rpcOK(w, r)
		case WellKnownPath:
			http.Redirect(w, r, "/cards/agent.json", http.StatusFound)
		case "/cards/agent.json":
			json.NewEncoder(w).Encode(Card{Name: "Agent", Skills: []Skill{{ID: "work", Name: "Work"}}})
		default:
			http.NotFound(w, r)
		}
	})

	c := &Client{URL: vendor.URL + "/rpc", Credential: "VENDOR-SECRET"}
	res, err := c.Send(context.Background(), "hi", SendOpts{NoWait: true})
	if err != nil {
		t.Fatalf("Send through a redirect within the origin: %v", err)
	}
	if res.Text != "done" {
		t.Errorf("Send result = %+v", res)
	}
	if auth, _ := vendor.last(); auth != "Bearer VENDOR-SECRET" {
		t.Errorf("the credential was dropped on a redirect within the origin: got %q", auth)
	}

	if _, err := FetchCard(context.Background(), vendor.URL, "VENDOR-SECRET"); err != nil {
		t.Errorf("FetchCard through a redirect within the origin: %v", err)
	}
}

// A client the caller supplies gets the same policy, ahead of its own: its own redirect policy
// cannot let a request leave the origin, and still applies within it.
func TestClient_SuppliedHTTPClientKeepsThePolicy(t *testing.T) {
	other := newSpyServer(t, rpcOK)
	vendor := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, other.URL+"/rpc", http.StatusTemporaryRedirect)
		case "/within":
			http.Redirect(w, r, "/rpc", http.StatusTemporaryRedirect)
		default:
			rpcOK(w, r)
		}
	})

	var ownPolicyCalls atomic.Int32
	allowAll := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		ownPolicyCalls.Add(1)
		return nil
	}}
	c := &Client{URL: vendor.URL + "/away", Credential: "VENDOR-SECRET", HTTP: allowAll}
	if _, err := c.Send(context.Background(), "hi", SendOpts{NoWait: true}); !errors.Is(err, ErrRedirectOrigin) {
		t.Errorf("Send error = %v, want one that wraps ErrRedirectOrigin", err)
	}
	if n := other.hits.Load(); n != 0 {
		t.Errorf("the other origin received %d request(s) through the supplied client", n)
	}
	if n := ownPolicyCalls.Load(); n != 0 {
		t.Errorf("the supplied client's policy was consulted %d time(s) for a redirect that was already refused", n)
	}

	c = &Client{URL: vendor.URL + "/within", Credential: "VENDOR-SECRET", HTTP: allowAll}
	if _, err := c.Send(context.Background(), "hi", SendOpts{NoWait: true}); err != nil {
		t.Errorf("Send through a redirect within the origin: %v", err)
	}
	if n := ownPolicyCalls.Load(); n != 1 {
		t.Errorf("the supplied client's own policy was consulted %d time(s) within the origin, want 1", n)
	}
	if allowAll.CheckRedirect == nil {
		t.Error("the supplied client was modified")
	}
}

// Setting a redirect policy switches off net/http's own limit of 10, so the policy keeps one:
// an agent that redirects to itself for ever is given up on.
func TestClient_RedirectLoopStops(t *testing.T) {
	vendor := newSpyServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/rpc", http.StatusTemporaryRedirect)
	})
	c := &Client{URL: vendor.URL + "/rpc"}
	_, err := c.Send(context.Background(), "hi", SendOpts{NoWait: true})
	if err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Errorf("Send error = %v, want the redirect limit", err)
	}
	if n := vendor.hits.Load(); n != maxRedirects {
		t.Errorf("the agent received %d requests, want %d", n, maxRedirects)
	}
}
