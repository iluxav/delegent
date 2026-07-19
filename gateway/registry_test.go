package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/store"
)

// fakeInstance is a stand-in gateway: it answers with its own build number so tests can tell
// a cached instance from a rebuilt one, and records Close.
type fakeInstance struct {
	n      int
	closed atomic.Bool
}

func (f *fakeInstance) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "gw-%d", f.n)
	})
}
func (f *fakeInstance) Close() { f.closed.Store(true) }

// The fake carries no pending consents — the console surface is exercised against a real
// gateway in console_test.go, not this HTTP-routing fake.
func (f *fakeInstance) PendingViews(string) []PendingView { return nil }
func (f *fakeInstance) ResolvePending(string, consoleDecision) (bool, bool, string) {
	return false, false, "no such request"
}

// testRegistry returns a Registry whose builder mints fakeInstances, plus the store, the
// build counter, and a mux mounting it the way cmd/api does.
func testRegistry(t *testing.T) (*Registry, *store.MemStore, *atomic.Int32, http.Handler) {
	t.Helper()
	st := store.NewMemStore()
	_ = st.PutTarget(context.Background(), &store.Target{ID: "tgt", Name: "T", Kind: "mcp", Endpoint: "http://x/mcp", Enabled: true})

	r := NewRegistry(st, keyring.Sealer(nil))
	var builds atomic.Int32
	r.build = func(ctx context.Context, st store.Store, sealer keyring.Sealer, target *store.Target) (instance, error) {
		return &fakeInstance{n: int(builds.Add(1))}, nil
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp/{target}", r)
	return r, st, &builds, mux
}

func do(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", path, nil))
	return rec.Code, rec.Body.String()
}

func TestRegistry_LazyBuildAndCache(t *testing.T) {
	_, _, builds, mux := testRegistry(t)

	if builds.Load() != 0 {
		t.Fatal("nothing should build before the first request")
	}
	if code, body := do(t, mux, "/mcp/tgt"); code != 200 || body != "gw-1" {
		t.Fatalf("first request: %d %q", code, body)
	}
	if code, body := do(t, mux, "/mcp/tgt"); code != 200 || body != "gw-1" {
		t.Fatalf("second request should hit the CACHED instance: %d %q", code, body)
	}
	if builds.Load() != 1 {
		t.Fatalf("want exactly 1 build, got %d", builds.Load())
	}
}

func TestRegistry_UnknownTarget404(t *testing.T) {
	_, _, builds, mux := testRegistry(t)
	if code, _ := do(t, mux, "/mcp/nope"); code != 404 {
		t.Fatalf("unknown target should be 404, got %d", code)
	}
	if builds.Load() != 0 {
		t.Fatal("unknown target must not trigger a build")
	}
}

func TestRegistry_DisabledTarget404(t *testing.T) {
	_, st, builds, mux := testRegistry(t)
	tg, _ := st.GetTarget(context.Background(), "tgt")
	tg.Enabled = false
	_ = st.PutTarget(context.Background(), tg)

	if code, _ := do(t, mux, "/mcp/tgt"); code != 404 {
		t.Fatalf("disabled target should be 404, got %d", code)
	}
	if builds.Load() != 0 {
		t.Fatal("disabled target must not trigger a build")
	}
}

func TestRegistry_InvalidateClosesAndRebuilds(t *testing.T) {
	r, _, _, mux := testRegistry(t)

	if _, body := do(t, mux, "/mcp/tgt"); body != "gw-1" {
		t.Fatalf("first build: %q", body)
	}
	first := r.slots["tgt"].gw.(*fakeInstance)

	r.Invalidate("tgt")
	if !first.closed.Load() {
		t.Fatal("invalidate should Close the cached instance")
	}
	if code, body := do(t, mux, "/mcp/tgt"); code != 200 || body != "gw-2" {
		t.Fatalf("after invalidate a FRESH instance should serve: %d %q", code, body)
	}
	// invalidating an id that was never built is a no-op
	r.Invalidate("never-built")
}

func TestRegistry_FailedBuildNotCached(t *testing.T) {
	r, _, _, mux := testRegistry(t)
	fail := true
	var builds atomic.Int32
	r.build = func(ctx context.Context, st store.Store, sealer keyring.Sealer, target *store.Target) (instance, error) {
		builds.Add(1)
		if fail {
			return nil, errors.New("upstream down")
		}
		return &fakeInstance{n: int(builds.Load())}, nil
	}

	if code, _ := do(t, mux, "/mcp/tgt"); code != 502 {
		t.Fatalf("failed build should be 502, got %d", code)
	}
	fail = false
	if code, body := do(t, mux, "/mcp/tgt"); code != 200 || body != "gw-2" {
		t.Fatalf("next request should RETRY the build: %d %q", code, body)
	}
}

func TestRegistry_SingleFlight(t *testing.T) {
	r, _, _, mux := testRegistry(t)

	// a slow builder: every concurrent first request must wait for ONE build
	var builds atomic.Int32
	gate := make(chan struct{})
	r.build = func(ctx context.Context, st store.Store, sealer keyring.Sealer, target *store.Target) (instance, error) {
		builds.Add(1)
		<-gate
		return &fakeInstance{n: 1}, nil
	}

	const n = 8
	var wg sync.WaitGroup
	bodies := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, bodies[i] = do(t, mux, "/mcp/tgt")
		}(i)
	}
	close(gate)
	wg.Wait()

	if builds.Load() != 1 {
		t.Fatalf("concurrent first requests should share ONE build, got %d", builds.Load())
	}
	for i, b := range bodies {
		if b != "gw-1" {
			t.Fatalf("request %d served by wrong instance: %q", i, b)
		}
	}
}
