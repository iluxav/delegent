package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway/store"
)

// TestConsentModePrecedence pins the routing table: elicitation > widget > console > denied,
// and the DELEGENT_CONSOLE_CONSENT off-switch collapsing the console channel to fail-closed.
// (DELEGENT_AUTOGRANT is a higher override still, but it bypasses mode routing in vendorTool —
// see TestConsoleAutograntBypass-style coverage in the e2e; it is not part of consentMode.)
func TestConsentModePrecedence(t *testing.T) {
	cases := []struct {
		name          string
		elic, ui, con bool
		want          consentMode
	}{
		{"elicitation wins", true, false, true, consentInline},
		{"elicitation over widget", true, true, true, consentInline},
		{"widget when no elicitation", false, true, true, consentWidget},
		{"console when neither, console on", false, false, true, consentConsole},
		{"denied when neither, console OFF", false, false, false, consentDenied},
		{"elicitation even with console off", true, false, false, consentInline},
		{"widget even with console off", false, true, false, consentWidget},
	}
	for _, c := range cases {
		got := clientCaps{elicitation: c.elic, uiExt: c.ui}.consentMode(c.con, featureFlags{}, nil)
		if got != c.want {
			t.Errorf("%s: consentMode(caps{elic=%v,ui=%v}, console=%v) = %q, want %q",
				c.name, c.elic, c.ui, c.con, got, c.want)
		}
	}
}

// TestConsentModeFeatureFlags: a bypass flag force-disables a channel so a capable client
// falls through to the next — never to something LESS strict than fail-closed.
func TestConsentModeFeatureFlags(t *testing.T) {
	full := clientCaps{elicitation: true, uiExt: true}
	// Bypass elicitation → the elicitation-capable client uses the widget instead.
	if got := full.consentMode(true, featureFlags{bypassElicitation: true}, nil); got != consentWidget {
		t.Fatalf("bypassElicitation: got %q, want widget", got)
	}
	// Bypass both → falls through to console.
	if got := full.consentMode(true, featureFlags{bypassElicitation: true, bypassWidget: true}, nil); got != consentConsole {
		t.Fatalf("bypass both: got %q, want console", got)
	}
	// Bypass both with console OFF → fail closed, never grants.
	if got := full.consentMode(false, featureFlags{bypassElicitation: true, bypassWidget: true}, nil); got != consentDenied {
		t.Fatalf("bypass both + console off: got %q, want denied", got)
	}
	// Bypass widget only → an elicitation-capable client is unaffected (still inline).
	if got := full.consentMode(true, featureFlags{bypassWidget: true}, nil); got != consentInline {
		t.Fatalf("bypassWidget on an elicitation client: got %q, want inline", got)
	}
}

func TestConsoleConsentFromEnv(t *testing.T) {
	t.Setenv("DELEGENT_CONSOLE_CONSENT", "")
	if !consoleConsentFromEnv() {
		t.Error("console consent must default ON")
	}
	t.Setenv("DELEGENT_CONSOLE_CONSENT", "off")
	if consoleConsentFromEnv() {
		t.Error("DELEGENT_CONSOLE_CONSENT=off must disable console consent")
	}
	t.Setenv("DELEGENT_CONSOLE_CONSENT", "OFF")
	if consoleConsentFromEnv() {
		t.Error("the off switch must be case-insensitive")
	}
	t.Setenv("DELEGENT_CONSOLE_CONSENT", "on")
	if !consoleConsentFromEnv() {
		t.Error("any value other than off keeps console consent ON")
	}
}

func TestConsentSyncWaitFromEnv(t *testing.T) {
	// Empty everything → the 25s default.
	t.Setenv("DELEGENT_CONSENT_SYNC_WAIT", "")
	t.Setenv("DELEGENT_CONSOLE_DECISION_WAIT", "")
	if got := consentSyncWaitFromEnv(); got != defaultConsentSyncWait {
		t.Errorf("empty must fall back to default 25s, got %s", got)
	}
	// SYNC_WAIT parsed (duration and bare seconds).
	t.Setenv("DELEGENT_CONSENT_SYNC_WAIT", "2s")
	if got := consentSyncWaitFromEnv(); got != 2*time.Second {
		t.Errorf("duration string not parsed, got %s", got)
	}
	t.Setenv("DELEGENT_CONSENT_SYNC_WAIT", "45")
	if got := consentSyncWaitFromEnv(); got != 45*time.Second {
		t.Errorf("bare seconds not parsed, got %s", got)
	}
	// Back-compat alias: DECISION_WAIT used only when SYNC_WAIT is unset.
	t.Setenv("DELEGENT_CONSENT_SYNC_WAIT", "")
	t.Setenv("DELEGENT_CONSOLE_DECISION_WAIT", "7s")
	if got := consentSyncWaitFromEnv(); got != 7*time.Second {
		t.Errorf("DECISION_WAIT alias not honored, got %s", got)
	}
	// SYNC_WAIT wins over the alias.
	t.Setenv("DELEGENT_CONSENT_SYNC_WAIT", "3s")
	t.Setenv("DELEGENT_CONSOLE_DECISION_WAIT", "99s")
	if got := consentSyncWaitFromEnv(); got != 3*time.Second {
		t.Errorf("SYNC_WAIT must win over the alias, got %s", got)
	}
}

func TestConsentRequestTTLFromEnv(t *testing.T) {
	t.Setenv("DELEGENT_CONSENT_REQUEST_TTL", "")
	if got := consentRequestTTLFromEnv(); got != defaultConsentRequestTTL {
		t.Errorf("empty must fall back to default 30m, got %s", got)
	}
	t.Setenv("DELEGENT_CONSENT_REQUEST_TTL", "10m")
	if got := consentRequestTTLFromEnv(); got != 10*time.Minute {
		t.Errorf("duration string not parsed, got %s", got)
	}
	t.Setenv("DELEGENT_CONSENT_REQUEST_TTL", "5")
	if got := consentRequestTTLFromEnv(); got != 5*time.Minute {
		t.Errorf("bare minutes not parsed, got %s", got)
	}
	t.Setenv("DELEGENT_CONSENT_REQUEST_TTL", "garbage")
	if got := consentRequestTTLFromEnv(); got != defaultConsentRequestTTL {
		t.Errorf("unparseable must fall back to default, got %s", got)
	}
}

// consoleRegistry wraps a console-capable scopeGateway in a Registry slot so the API-facing
// Registry.PendingConsents/ResolveConsent can be exercised end to end.
func consoleRegistry(t *testing.T) (*Registry, *Gateway) {
	t.Helper()
	g := scopeGateway(t, grantScopeConnection)
	g.consoleConsent = true
	r := &Registry{st: g.st, slots: map[string]*slot{}, hub: newConsentHub()}
	r.slots[g.targetID] = &slot{gw: g}
	g.hub = r.hub
	return r, g
}

func resultText(res *mcp.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

// waitForPending polls the console read model until exactly one request is parked (or fails).
func waitForPending(t *testing.T, r *Registry, owner string) PendingView {
	t.Helper()
	for i := 0; i < 400; i++ {
		vs := r.PendingConsents(owner)
		if len(vs) == 1 {
			return vs[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("a parked console consent never appeared in PendingConsents")
	return PendingView{}
}

// TestConsolePendingAndResolveGrant: a console-mode call parks and BLOCKS; PendingConsents shows
// it with the requesting-agent name and the advisor's human scope text; a console GRANT unblocks
// the call with a granted result and the connection then holds the scope.
func TestConsolePendingAndResolveGrant(t *testing.T) {
	r, g := consoleRegistry(t)

	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		done <- g.consoleConsentBlock(context.Background(), "conn1", "read_file", []string{"files:read"}, callMeta{Tool: "read_file", Target: g.targetID})
	}()

	pv := waitForPending(t, r, "root:alice")
	if pv.Principal != "root:alice" {
		t.Fatalf("pending principal = %q, want root:alice", pv.Principal)
	}
	if pv.AgentName == "" {
		t.Error("pending view must carry the requesting-agent name")
	}
	if len(pv.Scopes) != 1 || pv.Scopes[0].Scope != "files:read" {
		t.Fatalf("pending scopes = %+v, want [files:read]", pv.Scopes)
	}
	if pv.Scopes[0].Human == "" {
		t.Error("scope row must carry the advisor's human text")
	}
	// Owner filter: another operator sees nothing.
	if got := r.PendingConsents("root:bob"); len(got) != 0 {
		t.Fatalf("owner filter leaked another principal's request: %+v", got)
	}

	ok, err := r.ResolveConsent(pv.Principal, pv.ID, []string{"files:read"}, 60, 1)
	if err != nil || !ok {
		t.Fatalf("ResolveConsent grant failed: ok=%v err=%v", ok, err)
	}

	select {
	case res := <-done:
		if res.IsError {
			t.Fatalf("granted console call returned an error result: %q", resultText(res))
		}
		if txt := resultText(res); txt == "" || !containsFold(txt, "granted") {
			t.Fatalf("blocked call did not return the grant outcome: %q", txt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the GRANT did not unblock the console-mode call")
	}

	// The grant is really minted: the connection now authorizes read_file.
	h := g.resumeSession("conn1")
	if h == "" {
		t.Fatal("connection has no session after the grant")
	}
	if _, d, okA := g.br.Authorize(h, toolReq("read_file")); !okA || !d.Allow {
		t.Fatalf("granted session does not authorize read_file: allow=%v", d.Allow)
	}
	// The request cleared from the read model.
	if got := r.PendingConsents(""); len(got) != 0 {
		t.Fatalf("resolved request still listed as pending: %+v", got)
	}
	// The durable row was finalized: approved, with the decided scopes and a resolution time.
	row, err := g.st.GetConsentRequest(context.Background(), pv.ID)
	if err != nil {
		t.Fatalf("durable consent row missing after grant: %v", err)
	}
	if row.Status != "approved" {
		t.Fatalf("durable row status = %q, want approved", row.Status)
	}
	if len(row.DecidedScopes) != 1 || row.DecidedScopes[0] != "files:read" {
		t.Fatalf("durable row decided_scopes = %+v, want [files:read]", row.DecidedScopes)
	}
	if row.ResolvedAt == 0 {
		t.Error("durable row must carry a resolved_at after the grant")
	}
}

// TestConsoleResolveDeny: a console DENY (empty granted) fails the blocked call closed.
func TestConsoleResolveDeny(t *testing.T) {
	r, g := consoleRegistry(t)
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		done <- g.consoleConsentBlock(context.Background(), "conn1", "read_file", []string{"files:read"}, callMeta{Tool: "read_file", Target: g.targetID})
	}()
	pv := waitForPending(t, r, "")

	ok, err := r.ResolveConsent(pv.Principal, pv.ID, nil, 0, 0) // empty granted = deny
	if err != nil || !ok {
		t.Fatalf("ResolveConsent deny failed: ok=%v err=%v", ok, err)
	}
	select {
	case res := <-done:
		if !res.IsError {
			t.Fatalf("denied console call must be an error result, got: %q", resultText(res))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the DENY did not unblock the console-mode call")
	}
	if h := g.resumeSession("conn1"); h != "" {
		t.Fatalf("a denied request must mint no session, got %q", h)
	}
	// The durable row was finalized to denied.
	row, err := g.st.GetConsentRequest(context.Background(), pv.ID)
	if err != nil {
		t.Fatalf("durable row missing after deny: %v", err)
	}
	if row.Status != "denied" || row.ResolvedAt == 0 {
		t.Fatalf("durable row after deny = %+v, want status=denied with resolved_at", row)
	}
}

// TestConsoleResolveUnknownID: an id no gateway holds resolves to ok=false, never a panic.
func TestConsoleResolveUnknownID(t *testing.T) {
	r, _ := consoleRegistry(t)
	if ok, err := r.ResolveConsent("root:alice", "does-not-exist", []string{"files:read"}, 60, 1); ok || err != nil {
		t.Fatalf("unknown id must be ok=false,nil, got ok=%v err=%v", ok, err)
	}
}

// TestConsoleResolveWrongOwner: a real, live pending id cannot be resolved by a DIFFERENT
// operator — the record must still be grantable by its true owner afterwards (nonce not burned).
func TestConsoleResolveWrongOwner(t *testing.T) {
	r, g := consoleRegistry(t)
	go g.consoleConsentBlock(context.Background(), "connX", "read_file", []string{"files:read"}, callMeta{Tool: "read_file", Target: g.targetID})
	pv := waitForPending(t, r, "root:alice")

	if ok, err := r.ResolveConsent("root:mallory", pv.ID, []string{"files:read"}, 60, 1); ok || err != nil {
		t.Fatalf("wrong-owner resolve must be ok=false,nil, got ok=%v err=%v", ok, err)
	}
	// The true owner can still grant — the mismatched attempt must not have burned the nonce.
	if ok, err := r.ResolveConsent("root:alice", pv.ID, []string{"files:read"}, 60, 1); !ok || err != nil {
		t.Fatalf("true-owner resolve after a wrong-owner attempt failed: ok=%v err=%v", ok, err)
	}
}

// TestConsolePendingAfterSyncWait: with no same-turn decision, the short sync window returns a
// NON-error "pending — retry shortly" and the durable row stays pending (approvable). No session
// is minted yet — the human may approve anytime, and the agent's retry then succeeds.
func TestConsolePendingAfterSyncWait(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	g.consoleConsent = true
	g.syncWait = 20 * time.Millisecond

	start := time.Now()
	res := g.consoleConsentBlock(context.Background(), "conn1", "read_file", []string{"files:read"}, callMeta{Tool: "read_file", Target: g.targetID})
	if time.Since(start) > time.Second {
		t.Fatal("the short sync-wait override was not honored")
	}
	if res.IsError {
		t.Fatalf("an unanswered console consent must return a NON-error pending result, got error: %q", resultText(res))
	}
	if txt := resultText(res); !containsFold(txt, "pending") || !containsFold(txt, "retry") {
		t.Fatalf("pending result should tell the agent it is pending and to retry, got: %q", txt)
	}
	if h := g.resumeSession("conn1"); h != "" {
		t.Fatal("a still-pending request must mint no session")
	}
	// The durable row persists as pending.
	rows, err := g.st.ListConsentRequests(context.Background(), "root:alice", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Status != "pending" {
		t.Fatalf("expected one pending durable row, got: %+v", rows)
	}
}

// TestConsoleLaterGrantNoWaiter is the ASYNC CORE: the call returns pending (no waiter remains),
// then a human approves LATER — ResolvePending must mint a session bound to the requesting
// connection so a retry resumes it, and finalize the row to approved.
func TestConsoleLaterGrantNoWaiter(t *testing.T) {
	r, g := consoleRegistry(t)
	g.syncWait = 15 * time.Millisecond

	// Same-turn window elapses with nobody deciding: pending, no session, no blocked waiter.
	res := g.consoleConsentBlock(context.Background(), "connZ", "read_file", []string{"files:read"}, callMeta{Tool: "read_file", Target: g.targetID})
	if res.IsError || !containsFold(resultText(res), "pending") {
		t.Fatalf("expected a non-error pending result, got isError=%v %q", res.IsError, resultText(res))
	}
	pv := waitForPending(t, r, "root:alice")

	// A human approves anytime — with NO call blocked on the record.
	ok, err := r.ResolveConsent(pv.Principal, pv.ID, []string{"files:read"}, 60, 1)
	if err != nil || !ok {
		t.Fatalf("late ResolveConsent grant failed: ok=%v err=%v", ok, err)
	}
	// The session is minted AND bound to the requesting connection, so the retry resumes it.
	h := g.resumeSession("connZ")
	if h == "" {
		t.Fatal("late grant did not bind a session to the requesting connection")
	}
	if _, d, okA := g.br.Authorize(h, toolReq("read_file")); !okA || !d.Allow {
		t.Fatalf("late-granted session does not authorize read_file: allow=%v", d.Allow)
	}
	row, err := g.st.GetConsentRequest(context.Background(), pv.ID)
	if err != nil || row.Status != "approved" {
		t.Fatalf("row not approved after late grant: %+v err=%v", row, err)
	}
}

// TestConsoleDedupReusesRow: a retry (same principal+conn+scopeset) reuses ONE record and ONE
// durable row rather than parking a duplicate.
func TestConsoleDedupReusesRow(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	g.consoleConsent = true
	g.syncWait = 10 * time.Millisecond

	res1 := g.consoleConsentBlock(context.Background(), "conn1", "read_file", []string{"files:read"}, callMeta{Tool: "read_file", Target: g.targetID})
	res2 := g.consoleConsentBlock(context.Background(), "conn1", "read_file", []string{"files:read"}, callMeta{Tool: "read_file", Target: g.targetID})
	if res1.IsError || res2.IsError {
		t.Fatalf("both parks must be non-error pending results: %q / %q", resultText(res1), resultText(res2))
	}
	rows, err := g.st.ListConsentRequests(context.Background(), "root:alice", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("a retry must reuse ONE durable row, got %d: %+v", len(rows), rows)
	}
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && indexFold(s, sub) >= 0
}

func indexFold(s, sub string) int {
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		ok := true
		for j := 0; j < len(sub); j++ {
			if lower(s[i+j]) != lower(sub[j]) {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// TestConsoleResolveOrphanExpires: after a gateway rebuild the in-memory record is gone but a
// pending DB row remains. Resolving it must NOT grant (fail closed) and must reconcile the row
// to "expired" so the ledger self-corrects rather than showing a ghost approvable request.
func TestConsoleResolveOrphanExpires(t *testing.T) {
	r, g := consoleRegistry(t)
	ctx := context.Background()

	// A pending row with no matching in-memory record (simulates a rebuilt gateway).
	row := &store.ConsentRequest{
		ID: "creq_orphan", TargetID: g.targetID, Principal: "root:alice",
		Scopes: []string{"files:read"}, Reason: "read", Status: "pending",
		CreatedAt: 1, ExpiresAt: nowMillis() + 600000,
	}
	if err := g.st.PutConsentRequest(ctx, row); err != nil {
		t.Fatal(err)
	}

	ok, err := r.ResolveConsent("root:alice", "creq_orphan", []string{"files:read"}, 60, 1)
	if ok || err != nil {
		t.Fatalf("orphan resolve must be ok=false,nil (no grant), got ok=%v err=%v", ok, err)
	}
	got, err := g.st.GetConsentRequest(ctx, "creq_orphan")
	if err != nil || got.Status != "expired" || got.ResolvedAt == 0 {
		t.Fatalf("orphan row must be reconciled to expired, got %+v err=%v", got, err)
	}
	// Wrong owner must NOT touch the row.
	row2 := &store.ConsentRequest{ID: "creq_other", TargetID: g.targetID, Principal: "root:alice",
		Scopes: []string{"files:read"}, Status: "pending", CreatedAt: 1, ExpiresAt: nowMillis() + 600000}
	_ = g.st.PutConsentRequest(ctx, row2)
	r.ResolveConsent("root:mallory", "creq_other", nil, 0, 0)
	if got, _ := g.st.GetConsentRequest(ctx, "creq_other"); got.Status != "pending" {
		t.Fatalf("wrong-owner resolve must not touch the row, status=%q", got.Status)
	}
}
