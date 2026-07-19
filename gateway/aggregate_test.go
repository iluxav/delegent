package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway/store"
)

// The aggregate serves ALL of a user's entitled, enabled targets on one MCP endpoint (/mcp):
// vendor tools are namespaced "<target>__<tool>" and route to the per-target gateway, so
// sessions, scopes, and consent stay target-scoped while the client configures ONE server.

func aggFixture(t *testing.T) *Registry {
	t.Helper()
	st := store.NewMemStore()
	ctx := context.Background()
	_ = st.PutUser(ctx, &store.User{ID: "usr_op"})
	for _, id := range []string{"gh", "tv", "off", "other"} {
		_ = st.PutAdapter(ctx, &store.AdapterDoc{ID: id, Name: id, Doc: []byte(`{"vendor":"` + id + `"}`)})
		_ = st.PutTarget(ctx, &store.Target{ID: id, Name: id, Kind: "mcp", Endpoint: "http://" + id + "/mcp",
			AdapterID: id, Owner: "usr_op", Enabled: id != "off"})
	}
	// usr_op is entitled on gh, tv, and the DISABLED off — but NOT on "other"
	for _, id := range []string{"gh", "tv", "off"} {
		_ = st.PutEntitlement(ctx, &store.Entitlement{UserID: "usr_op", TargetID: id, Scopes: []string{"mcp:connect"}})
	}

	r := &Registry{st: st, slots: map[string]*slot{}, hub: newConsentHub(), aggregates: map[string]*Aggregate{}}
	for _, id := range []string{"gh", "tv", "off", "other"} {
		g := &Gateway{targetID: id, st: st,
			byConn: map[string]string{}, byConnCaps: map[string]clientCaps{}, byConnMeta: map[string]callMeta{}, byConnPolicy: map[string][]string{},
		}
		switch id {
		case "gh":
			g.vendorToolInfos = []*mcp.Tool{
				{Name: "create_issue", Description: "open an issue"},
				{Name: "search", Description: "search code"},
			}
		case "tv", "off", "other":
			g.vendorToolInfos = []*mcp.Tool{{Name: "search", Description: "web search"}}
		}
		r.slots[id] = &slot{gw: g}
	}
	return r
}

func TestAggregateAssembly(t *testing.T) {
	r := aggFixture(t)
	a, err := newAggregate(context.Background(), r, "usr_op")
	if err != nil {
		t.Fatalf("newAggregate: %v", err)
	}
	// entitled+enabled targets only, deterministic order
	if strings.Join(a.targets, ",") != "gh,tv" {
		t.Fatalf("targets = %v, want [gh tv] (off is disabled, other unentitled)", a.targets)
	}
	// namespaced, collision-free tools ("search" exists on both targets)
	for _, ns := range []string{"gh__create_issue", "gh__search", "tv__search"} {
		route, ok := a.routes[ns]
		if !ok {
			t.Fatalf("missing route %q (routes: %v)", ns, a.routes)
		}
		want := strings.SplitN(ns, "__", 2)
		if route.targetID != want[0] || route.tool != want[1] {
			t.Fatalf("route %q = %+v", ns, route)
		}
	}
	if _, ok := a.routes["off__search"]; ok {
		t.Fatal("disabled target leaked into the aggregate")
	}
	if _, ok := a.routes["other__search"]; ok {
		t.Fatal("unentitled target leaked into the aggregate")
	}
}

func TestAggregateResolveTarget(t *testing.T) {
	r := aggFixture(t)
	a, _ := newAggregate(context.Background(), r, "usr_op")

	// explicit target always wins
	if got, errText := a.resolveTarget("conn1", "tv"); got != "tv" || errText != "" {
		t.Fatalf("explicit: %q %q", got, errText)
	}
	// unknown explicit target: helpful error naming the real ones
	if _, errText := a.resolveTarget("conn1", "nope"); !strings.Contains(errText, "gh") || !strings.Contains(errText, "tv") {
		t.Fatalf("unknown target error should list targets: %q", errText)
	}
	// no explicit + no history: ambiguous with 2 targets
	if _, errText := a.resolveTarget("conn1", ""); errText == "" {
		t.Fatal("ambiguous resolution must error")
	}
	// after a vendor call routed to gh, entry tools follow it
	a.noteTarget("conn1", "gh")
	if got, errText := a.resolveTarget("conn1", ""); got != "gh" || errText != "" {
		t.Fatalf("lastTarget fallback: %q %q", got, errText)
	}
	// other connections are unaffected
	if _, errText := a.resolveTarget("conn2", ""); errText == "" {
		t.Fatal("conn isolation broken")
	}
}

// prepareCall must propagate the aggregate connection's client caps and key policy into the
// target gateway, so its consent-mode routing (elicitation vs widget vs console) behaves
// exactly as a direct connection would.
func TestAggregatePropagatesCapsAndPolicy(t *testing.T) {
	r := aggFixture(t)
	a, _ := newAggregate(context.Background(), r, "usr_op")
	a.setCaps("conn1", clientCaps{elicitation: true})

	g := r.slots["gh"].gw.(*Gateway)
	a.prepareCall(context.Background(), "conn1", "gh", g)
	if !g.capsOf("conn1").elicitation {
		t.Fatal("caps not propagated to the target gateway")
	}
	if got, _ := a.resolveTarget("conn1", ""); got != "gh" {
		t.Fatalf("prepareCall should note the target: %q", got)
	}
}
