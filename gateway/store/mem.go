package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"delegent.dev/gateway/id"
)

// MemStore is the in-process Store: the dev default, the reference implementation the
// conformance suite trusts, and the path unit tests exercise with zero external
// dependencies. It deep-copies on the way in and out so callers cannot mutate stored state
// through a retained pointer — the same isolation a row read from a database gives you.
type MemStore struct {
	mu           sync.Mutex
	sessions     map[string]*Session
	receipts     []*Receipt
	events       []*Event
	escalations  map[string]*Escalation
	consentReqs  map[string]*ConsentRequest
	targets      map[string]*Target
	adapters     map[string]*AdapterDoc
	advisors     map[string]*AdvisorDoc
	oauthClients map[string]*OAuthClient // keyed by target ID
	oauthFlows   map[string]*OAuthFlow   // keyed by state (single-use PKCE flows)
	oauthPending map[string]*OAuthPending // keyed by state (target-less OAuth-first slots)
	users        map[string]*User        // keyed by user ID
	entitlements  map[string]*Entitlement       // keyed by userID|targetID
	channelConns    map[string]*ChannelConnection // keyed by userID|kind
	channelTokens   map[string]*ChannelLinkToken  // keyed by token
	channelSettings map[string]*ChannelSetting    // keyed by kind
	agentKeys    map[string]*AgentKey    // keyed by key ID
	secrets      map[string][]byte       // keyed by ref; opaque sealed bytes
}

// NewMemStore returns an empty in-memory Store.
func NewMemStore() *MemStore {
	return &MemStore{
		sessions:     map[string]*Session{},
		escalations:  map[string]*Escalation{},
		consentReqs:  map[string]*ConsentRequest{},
		targets:      map[string]*Target{},
		adapters:     map[string]*AdapterDoc{},
		advisors:     map[string]*AdvisorDoc{},
		oauthClients: map[string]*OAuthClient{},
		oauthFlows:   map[string]*OAuthFlow{},
		oauthPending: map[string]*OAuthPending{},
		users:        map[string]*User{},
		entitlements:  map[string]*Entitlement{},
		channelConns:    map[string]*ChannelConnection{},
		channelTokens:   map[string]*ChannelLinkToken{},
		channelSettings: map[string]*ChannelSetting{},
		agentKeys:    map[string]*AgentKey{},
		secrets:      map[string][]byte{},
	}
}

func cloneAgentKey(k *AgentKey) *AgentKey {
	cp := *k
	cp.Hash = append([]byte(nil), k.Hash...)
	cp.ConsentChannels = append([]string(nil), k.ConsentChannels...)
	return &cp
}

func (m *MemStore) SetAgentKeyConsentChannels(_ context.Context, id string, channels []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.agentKeys[id]
	if !ok {
		return ErrNotFound
	}
	k.ConsentChannels = append([]string(nil), channels...)
	return nil
}

func (m *MemStore) PutAgentKey(_ context.Context, k *AgentKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.agentKeys[k.ID]; exists {
		return fmt.Errorf("agent key %q already exists (keys are create-only)", k.ID)
	}
	m.agentKeys[k.ID] = cloneAgentKey(k)
	return nil
}

func (m *MemStore) GetAgentKey(_ context.Context, id string) (*AgentKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.agentKeys[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneAgentKey(k), nil
}

func (m *MemStore) GetAgentKeyByHash(_ context.Context, hash []byte) (*AgentKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.agentKeys {
		if bytesEqual(k.Hash, hash) {
			return cloneAgentKey(k), nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) ListAgentKeys(_ context.Context, userID string) ([]*AgentKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*AgentKey
	for _, k := range m.agentKeys {
		if k.UserID == userID {
			out = append(out, cloneAgentKey(k))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out, nil
}

func (m *MemStore) RevokeAgentKey(_ context.Context, id string, at int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.agentKeys[id]; ok {
		k.RevokedAt = at
	}
	return nil
}

func (m *MemStore) TouchAgentKey(_ context.Context, id string, at int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.agentKeys[id]; ok {
		k.LastUsedAt = at
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (m *MemStore) GetSecret(_ context.Context, ref string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.secrets[ref]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (m *MemStore) PutSecret(_ context.Context, ref string, sealed []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[ref] = append([]byte(nil), sealed...)
	return nil
}

// DeleteSecret removes a sealed blob. Deleting a nonexistent ref is a no-op (returns nil).
func (m *MemStore) DeleteSecret(_ context.Context, ref string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.secrets, ref)
	return nil
}

func (m *MemStore) PutSession(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.Handle] = cloneSession(s)
	return nil
}

func (m *MemStore) GetSession(_ context.Context, handle string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[handle]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneSession(s), nil
}

func (m *MemStore) ListSessions(_ context.Context, principal string) ([]*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Session
	for _, s := range m.sessions {
		if s.RevokedAt == 0 && (principal == "" || s.Principal == principal) {
			out = append(out, cloneSession(s))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

func (m *MemStore) Spend(_ context.Context, handle string, amount int64, entry LedgerEntry) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[handle]
	if !ok {
		return 0, ErrNotFound
	}
	if !s.HasBudget {
		return 0, nil // no ceiling configured — nothing to debit
	}
	if s.BudgetRemainingC-amount < 0 {
		return s.BudgetRemainingC, ErrInsufficientBudget
	}
	s.BudgetRemainingC -= amount
	return s.BudgetRemainingC, nil
}

func (m *MemStore) AppendReceipt(_ context.Context, r *Receipt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *r
	cp.Scopes = append([]string(nil), r.Scopes...)
	m.receipts = append(m.receipts, &cp)
	return nil
}

func (m *MemStore) ListReceipts(_ context.Context, f ReceiptFilter) ([]*Receipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Receipt
	for _, r := range m.receipts {
		if f.Principal != "" && r.Principal != f.Principal {
			continue
		}
		if f.Handle != "" && r.Handle != f.Handle {
			continue
		}
		cp := *r
		cp.Scopes = append([]string(nil), r.Scopes...)
		out = append(out, &cp)
	}
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[len(out)-f.Limit:]
	}
	return out, nil
}

// LastReceiptHash returns the Hash of the most recently appended receipt for principal (walking
// insertion order backwards), or "" when the principal has no receipts.
func (m *MemStore) LastReceiptHash(_ context.Context, principal string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.receipts) - 1; i >= 0; i-- {
		if m.receipts[i].Principal == principal {
			return m.receipts[i].Hash, nil
		}
	}
	return "", nil
}

func cloneEvent(e *Event) *Event {
	cp := *e
	cp.Scopes = append([]string(nil), e.Scopes...)
	cp.Params = append(json.RawMessage(nil), e.Params...)
	cp.Result = append(json.RawMessage(nil), e.Result...)
	return &cp
}

func (m *MemStore) AppendEvent(_ context.Context, e *Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := cloneEvent(e)
	if cp.ID == "" {
		cp.ID = id.New("evt")
	}
	if cp.CreatedAt == 0 {
		cp.CreatedAt = time.Now().UnixMilli()
	}
	m.events = append(m.events, cp)
	return nil
}

func (m *MemStore) ListEvents(_ context.Context, f EventFilter) ([]*Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	limit := f.Limit
	if limit <= 0 {
		limit = EventLimitDefault
	}
	if limit > EventLimitMax {
		limit = EventLimitMax
	}
	var out []*Event
	for _, e := range m.events {
		if f.UserID != "" && e.UserID != f.UserID {
			continue
		}
		if f.KeyName != "" && e.KeyName != f.KeyName {
			continue
		}
		if f.KeyPrefix != "" && e.KeyPrefix != f.KeyPrefix {
			continue
		}
		if f.Type != "" && e.Type != f.Type {
			continue
		}
		if f.TargetID != "" && e.TargetID != f.TargetID {
			continue
		}
		if f.Tool != "" && e.Tool != f.Tool {
			continue
		}
		if f.Decision != "" && e.Decision != f.Decision {
			continue
		}
		if f.Since != 0 && e.CreatedAt < f.Since {
			continue
		}
		if f.Until != 0 && e.CreatedAt > f.Until {
			continue
		}
		out = append(out, cloneEvent(e))
	}
	// newest-first; insertion order breaks ties (later append = newer).
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].ID > out[j].ID // deterministic tiebreak among same-ms events (every backend must match)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemStore) PutEscalation(_ context.Context, e *Escalation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *e
	cp.Scopes = append([]string(nil), e.Scopes...)
	m.escalations[e.ID] = &cp
	return nil
}

func (m *MemStore) GetEscalation(_ context.Context, id string) (*Escalation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.escalations[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *e
	cp.Scopes = append([]string(nil), e.Scopes...)
	return &cp, nil
}

func (m *MemStore) ListPendingEscalations(_ context.Context, parentHandle string) ([]*Escalation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Escalation
	for _, e := range m.escalations {
		if e.Status == "pending" && e.ParentHandle == parentHandle {
			cp := *e
			cp.Scopes = append([]string(nil), e.Scopes...)
			out = append(out, &cp)
		}
	}
	return out, nil
}

func cloneConsentRequest(r *ConsentRequest) *ConsentRequest {
	cp := *r
	cp.Scopes = append([]string(nil), r.Scopes...)
	cp.DecidedScopes = append([]string(nil), r.DecidedScopes...)
	return &cp
}

func (m *MemStore) PutConsentRequest(_ context.Context, r *ConsentRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consentReqs[r.ID] = cloneConsentRequest(r)
	return nil
}

func (m *MemStore) GetConsentRequest(_ context.Context, id string) (*ConsentRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.consentReqs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneConsentRequest(r), nil
}

func (m *MemStore) ListConsentRequests(_ context.Context, principal string, includeResolved bool) ([]*ConsentRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*ConsentRequest
	for _, r := range m.consentReqs {
		if principal != "" && r.Principal != principal {
			continue
		}
		if !includeResolved && r.Status != "pending" {
			continue
		}
		out = append(out, cloneConsentRequest(r))
	}
	// pending-first, then newest-first by CreatedAt.
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := out[i].Status == "pending", out[j].Status == "pending"
		if pi != pj {
			return pi
		}
		return out[i].CreatedAt > out[j].CreatedAt
	})
	return out, nil
}

func (m *MemStore) ExpireStaleConsentRequests(_ context.Context, now int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.consentReqs {
		if r.Status == "pending" && r.ExpiresAt != 0 && now > r.ExpiresAt {
			r.Status = "expired"
			r.ResolvedAt = now
			n++
		}
	}
	return n, nil
}

func (m *MemStore) GetTarget(_ context.Context, id string) (*Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.targets[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (m *MemStore) ListTargets(_ context.Context) ([]*Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Target, 0, len(m.targets))
	for _, t := range m.targets {
		cp := *t
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemStore) PutTarget(_ context.Context, t *Target) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *t
	m.targets[t.ID] = &cp
	return nil
}

func (m *MemStore) GetAdapter(_ context.Context, id string) (*AdapterDoc, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.adapters[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneAdapter(a), nil
}

func (m *MemStore) PutAdapter(_ context.Context, a *AdapterDoc) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.adapters[a.ID] = cloneAdapter(a)
	return nil
}

func (m *MemStore) GetAdvisor(_ context.Context, id string) (*AdvisorDoc, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.advisors[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneAdvisor(a), nil
}

func (m *MemStore) PutAdvisor(_ context.Context, a *AdvisorDoc) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.advisors[a.ID] = cloneAdvisor(a)
	return nil
}

func (m *MemStore) GetOAuthClient(_ context.Context, targetID string) (*OAuthClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.oauthClients[targetID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (m *MemStore) PutOAuthClient(_ context.Context, c *OAuthClient) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *c
	m.oauthClients[c.TargetID] = &cp
	return nil
}

func (m *MemStore) PutOAuthFlow(_ context.Context, f *OAuthFlow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *f
	m.oauthFlows[f.State] = &cp
	return nil
}

// TakeOAuthFlow returns a copy of the flow and deletes it, so a second call returns ErrNotFound
// (single-use: read-and-delete must be atomic in every backend).
func (m *MemStore) TakeOAuthFlow(_ context.Context, state string) (*OAuthFlow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.oauthFlows[state]
	if !ok {
		return nil, ErrNotFound
	}
	delete(m.oauthFlows, state)
	cp := *f
	return &cp, nil
}

func (m *MemStore) PutOAuthPending(_ context.Context, p *OAuthPending) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *p
	m.oauthPending[p.State] = &cp
	return nil
}

// GetOAuthPending returns a copy WITHOUT deleting it — the callback and wizard read the slot
// repeatedly before save consumes it via Take.
func (m *MemStore) GetOAuthPending(_ context.Context, state string) (*OAuthPending, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.oauthPending[state]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *p
	return &cp, nil
}

// TakeOAuthPending returns a copy of the slot and deletes it, so a second call returns
// ErrNotFound (single-use: read-and-delete must be atomic in every backend).
func (m *MemStore) TakeOAuthPending(_ context.Context, state string) (*OAuthPending, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.oauthPending[state]
	if !ok {
		return nil, ErrNotFound
	}
	delete(m.oauthPending, state)
	cp := *p
	return &cp, nil
}

// ExpireStalePending deletes pending rows created before olderThanUnix (unix seconds) along with
// their sealed token/client-secret blobs, and returns how many rows it swept.
func (m *MemStore) ExpireStalePending(_ context.Context, olderThanUnix int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for state, p := range m.oauthPending {
		if p.CreatedAt < olderThanUnix {
			if p.TokenRef != "" {
				delete(m.secrets, p.TokenRef)
			}
			if p.ClientSecretRef != "" {
				delete(m.secrets, p.ClientSecretRef)
			}
			delete(m.oauthPending, state)
			n++
		}
	}
	return n, nil
}

func (m *MemStore) GetUser(_ context.Context, id string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneUser(u), nil
}

func (m *MemStore) GetUserByExternal(_ context.Context, externalID string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.ExternalID != "" && u.ExternalID == externalID {
			return cloneUser(u), nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) ListUsers(_ context.Context) ([]*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, cloneUser(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemStore) PutUser(_ context.Context, u *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[u.ID] = cloneUser(u)
	return nil
}

func entKey(userID, targetID string) string { return userID + "|" + targetID }

func (m *MemStore) GetEntitlement(_ context.Context, userID, targetID string) (*Entitlement, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entitlements[entKey(userID, targetID)]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneEntitlement(e), nil
}

func (m *MemStore) ListEntitlementsForTarget(_ context.Context, targetID string) ([]*Entitlement, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Entitlement
	for _, e := range m.entitlements {
		if e.TargetID == targetID {
			out = append(out, cloneEntitlement(e))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UserID < out[j].UserID })
	return out, nil
}

func (m *MemStore) ListEntitlementsForUser(_ context.Context, userID string) ([]*Entitlement, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Entitlement
	for _, e := range m.entitlements {
		if e.UserID == userID {
			out = append(out, cloneEntitlement(e))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TargetID < out[j].TargetID })
	return out, nil
}

func (m *MemStore) PutEntitlement(_ context.Context, e *Entitlement) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entitlements[entKey(e.UserID, e.TargetID)] = cloneEntitlement(e)
	return nil
}

// --- channel connections + link tokens ---

func chanKey(userID, kind string) string { return userID + "|" + kind }

func (m *MemStore) PutChannelConnection(_ context.Context, c *ChannelConnection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *c
	m.channelConns[chanKey(c.UserID, c.Kind)] = &cp
	return nil
}

func (m *MemStore) GetChannelConnection(_ context.Context, userID, kind string) (*ChannelConnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.channelConns[chanKey(userID, kind)]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (m *MemStore) ListChannelConnections(_ context.Context, userID string) ([]*ChannelConnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*ChannelConnection
	for _, c := range m.channelConns {
		if c.UserID == userID {
			cp := *c
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out, nil
}

func (m *MemStore) DeleteChannelConnection(_ context.Context, userID, kind string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.channelConns[chanKey(userID, kind)]; !ok {
		return ErrNotFound
	}
	delete(m.channelConns, chanKey(userID, kind))
	return nil
}

func (m *MemStore) PutChannelSetting(_ context.Context, s *ChannelSetting) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *s
	cp.Settings = append(json.RawMessage(nil), s.Settings...)
	m.channelSettings[s.Kind] = &cp
	return nil
}

func (m *MemStore) GetChannelSetting(_ context.Context, kind string) (*ChannelSetting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.channelSettings[kind]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *s
	cp.Settings = append(json.RawMessage(nil), s.Settings...)
	return &cp, nil
}

func (m *MemStore) DeleteChannelSetting(_ context.Context, kind string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.channelSettings[kind]; !ok {
		return ErrNotFound
	}
	delete(m.channelSettings, kind)
	return nil
}

func (m *MemStore) PutChannelLinkToken(_ context.Context, t *ChannelLinkToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *t
	m.channelTokens[t.Token] = &cp
	return nil
}

func (m *MemStore) TakeChannelLinkToken(_ context.Context, token string, now int64) (*ChannelLinkToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.channelTokens[token]
	if !ok {
		return nil, ErrNotFound
	}
	delete(m.channelTokens, token) // consumed either way — an expired token is not retryable
	if now > t.ExpiresAt {
		return nil, ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (m *MemStore) Close() error { return nil }

// --- deep-copy helpers so retained pointers cannot mutate stored state ---

func cloneSession(s *Session) *Session {
	cp := *s
	cp.Chain = make([]SlipRow, len(s.Chain))
	for i, r := range s.Chain {
		cp.Chain[i] = SlipRow{Canonical: append([]byte(nil), r.Canonical...), Sig: r.Sig}
	}
	cp.SealedKey = append([]byte(nil), s.SealedKey...)
	cp.Scopes = append([]string(nil), s.Scopes...)
	cp.Ceiling = append([]string(nil), s.Ceiling...)
	return &cp
}

func cloneAdapter(a *AdapterDoc) *AdapterDoc {
	cp := *a
	cp.Doc = append(json.RawMessage(nil), a.Doc...)
	return &cp
}

func cloneAdvisor(a *AdvisorDoc) *AdvisorDoc {
	cp := *a
	cp.Doc = append(json.RawMessage(nil), a.Doc...)
	return &cp
}

func cloneUser(u *User) *User {
	cp := *u
	cp.SealedKey = append([]byte(nil), u.SealedKey...)
	return &cp
}

func cloneEntitlement(e *Entitlement) *Entitlement {
	cp := *e
	cp.Scopes = append([]string(nil), e.Scopes...)
	cp.Disabled = append([]string(nil), e.Disabled...)
	return &cp
}
