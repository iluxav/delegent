package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// cardServer serves an agent card whose URL is whatever cardURL returns for the server's own
// base URL, and counts the JSON-RPC calls it receives.
type cardServer struct {
	*httptest.Server
	rpcHits atomic.Int32
	rpcAuth atomic.Value
}

func newCardServer(t *testing.T, cardURL func(base string) string) *cardServer {
	t.Helper()
	s := &cardServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Card{Name: "Agent", URL: cardURL(s.URL), Skills: []Skill{{ID: "work", Name: "Work"}}})
	})
	mux.HandleFunc("POST /rpc", func(w http.ResponseWriter, r *http.Request) {
		s.rpcHits.Add(1)
		s.rpcAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusBadRequest)
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// A card is written by the agent, and every call goes to the URL it names, with the target's
// credential. FetchCard refuses a card whose URL is not on the origin of the endpoint the
// operator configured, so the agent cannot choose another host to receive them.
func TestFetchCard_RefusesCardURLOnAnotherOrigin(t *testing.T) {
	other := newCardServer(t, func(base string) string { return base + "/rpc" })

	cases := []struct {
		name     string
		endpoint func(base string) string // what the operator configured
		cardURL  func(base string) string // what the card names
	}{
		{
			name:     "another host and port",
			endpoint: func(base string) string { return base },
			cardURL:  func(string) string { return other.URL + "/rpc" },
		},
		{
			name:     "another name for the same machine",
			endpoint: func(base string) string { return strings.Replace(base, "127.0.0.1", "localhost", 1) },
			cardURL:  func(base string) string { return base + "/rpc" },
		},
		{
			name:     "the same host over https",
			endpoint: func(base string) string { return base },
			cardURL:  func(base string) string { return strings.Replace(base, "http://", "https://", 1) + "/rpc" },
		},
		{
			name:     "a url with no host",
			endpoint: func(base string) string { return base },
			cardURL:  func(string) string { return "/rpc" },
		},
	}
	for _, c := range cases {
		vendor := newCardServer(t, c.cardURL)
		endpoint := c.endpoint(vendor.URL)
		card, err := FetchCard(context.Background(), endpoint, "VENDOR-SECRET")
		if err == nil {
			t.Errorf("%s: FetchCard(%s) accepted a card whose URL is %s", c.name, endpoint, card.URL)
		}
	}
	if n := other.rpcHits.Load(); n != 0 {
		t.Errorf("the other host received %d call(s)", n)
	}
}

// A card on the endpoint's own origin is accepted whatever its path, and a card with no URL
// means the endpoint itself.
func TestFetchCard_AcceptsCardURLOnTheEndpointOrigin(t *testing.T) {
	for _, c := range []struct {
		name    string
		cardURL func(base string) string
		want    func(base string) string
	}{
		{"another path", func(base string) string { return base + "/rpc" }, func(base string) string { return base + "/rpc" }},
		{"no url", func(string) string { return "" }, func(base string) string { return base }},
	} {
		vendor := newCardServer(t, c.cardURL)
		card, err := FetchCard(context.Background(), vendor.URL, "VENDOR-SECRET")
		if err != nil {
			t.Errorf("%s: FetchCard: %v", c.name, err)
			continue
		}
		if want := c.want(vendor.URL); card.URL != want {
			t.Errorf("%s: card.URL = %q, want %q", c.name, card.URL, want)
		}
	}
}
