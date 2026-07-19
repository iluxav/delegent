package store

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// JSONFileStore is the local single-operator backend: MemStore semantics with durable state
// mirrored to plain JSON files in one directory. Every file except the sealed secrets blob is
// diffable canonical JSON — the on-disk formats double as the export/import format — and the
// receipt log is per-principal append-only JSONL, auditable offline with `delegent verify`.
//
// Deliberately ephemeral (memory-only, lost on restart): sessions and their budgets,
// escalations, in-flight OAuth PKCE flows, and channel link tokens — all short-lived
// single-use runtime state a restarted agent simply re-establishes.
type JSONFileStore struct {
	*MemStore
	dir string
	fmu sync.Mutex // serializes file writes so a later snapshot never loses to an earlier one
}

var _ Store = (*JSONFileStore)(nil)

const (
	fileUsers        = "users.json"
	fileTargets      = "targets.json"
	fileAdapters     = "adapters.json"
	fileAdvisors     = "advisors.json"
	fileAgentKeys    = "agent_keys.json"
	fileEntitlements = "entitlements.json"
	fileConsents     = "consent_requests.json"
	fileOAuthClients = "oauth_clients.json"
	fileOAuthPending = "oauth_pending.json"
	fileChannelConns = "channel_connections.json"
	fileChannelSets  = "channel_settings.json"
	fileSecrets      = "secrets.sealed"
	fileEvents       = "events.jsonl"
	dirReceipts      = "receipts"
)

// NewJSONFileStore opens (creating if absent) a file-backed store rooted at dir.
func NewJSONFileStore(dir string) (*JSONFileStore, error) {
	if err := os.MkdirAll(filepath.Join(dir, dirReceipts), 0o700); err != nil {
		return nil, fmt.Errorf("jsonfile: create %s: %w", dir, err)
	}
	js := &JSONFileStore{MemStore: NewMemStore(), dir: dir}
	if err := js.load(); err != nil {
		return nil, err
	}
	return js, nil
}

// --- loading ---

func loadInto[T any](path string, insert func(*T)) error {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var rows []*T
	if err := json.Unmarshal(raw, &rows); err != nil {
		return fmt.Errorf("jsonfile: parse %s: %w", filepath.Base(path), err)
	}
	for _, r := range rows {
		insert(r)
	}
	return nil
}

func loadLines[T any](path string, insert func(*T)) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		n++
		var row T
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return fmt.Errorf("jsonfile: parse %s line %d: %w", filepath.Base(path), n, err)
		}
		insert(&row)
	}
	return sc.Err()
}

func (js *JSONFileStore) load() error {
	m := js.MemStore
	p := func(name string) string { return filepath.Join(js.dir, name) }

	if err := loadInto(p(fileUsers), func(u *User) { m.users[u.ID] = u }); err != nil {
		return err
	}
	if err := loadInto(p(fileTargets), func(t *Target) { m.targets[t.ID] = t }); err != nil {
		return err
	}
	if err := loadInto(p(fileAdapters), func(a *AdapterDoc) { m.adapters[a.ID] = a }); err != nil {
		return err
	}
	if err := loadInto(p(fileAdvisors), func(a *AdvisorDoc) { m.advisors[a.ID] = a }); err != nil {
		return err
	}
	if err := loadInto(p(fileAgentKeys), func(k *AgentKey) { m.agentKeys[k.ID] = k }); err != nil {
		return err
	}
	if err := loadInto(p(fileEntitlements), func(e *Entitlement) { m.entitlements[entKey(e.UserID, e.TargetID)] = e }); err != nil {
		return err
	}
	if err := loadInto(p(fileConsents), func(r *ConsentRequest) { m.consentReqs[r.ID] = r }); err != nil {
		return err
	}
	if err := loadInto(p(fileOAuthClients), func(c *OAuthClient) { m.oauthClients[c.TargetID] = c }); err != nil {
		return err
	}
	if err := loadInto(p(fileOAuthPending), func(x *OAuthPending) { m.oauthPending[x.State] = x }); err != nil {
		return err
	}
	if err := loadInto(p(fileChannelConns), func(c *ChannelConnection) { m.channelConns[chanKey(c.UserID, c.Kind)] = c }); err != nil {
		return err
	}
	if err := loadInto(p(fileChannelSets), func(s *ChannelSetting) { m.channelSettings[s.Kind] = s }); err != nil {
		return err
	}

	if raw, err := os.ReadFile(p(fileSecrets)); err == nil {
		if err := json.Unmarshal(raw, &m.secrets); err != nil {
			return fmt.Errorf("jsonfile: parse %s: %w", fileSecrets, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := loadLines(p(fileEvents), func(e *Event) { m.events = append(m.events, e) }); err != nil {
		return err
	}

	// Receipts: one JSONL file per principal, chain order within each file. Merge stably by
	// CreatedAt — ties keep file order, so no principal's PrevHash linkage is ever reordered.
	entries, err := os.ReadDir(p(dirReceipts))
	if err != nil {
		return err
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".jsonl") {
			continue
		}
		if err := loadLines(filepath.Join(js.dir, dirReceipts, ent.Name()), func(r *Receipt) { m.receipts = append(m.receipts, r) }); err != nil {
			return err
		}
	}
	sort.SliceStable(m.receipts, func(i, j int) bool { return m.receipts[i].CreatedAt < m.receipts[j].CreatedAt })
	return nil
}

// --- persistence ---

// writeFileAtomic writes via a temp file + rename so a crash never leaves a torn file.
func (js *JSONFileStore) writeFileAtomic(name string, data []byte) error {
	path := filepath.Join(js.dir, name)
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(name)+".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func sortedVals[V any](m map[string]*V) []*V {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*V, 0, len(m))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

// save snapshots one collection under the MemStore lock and writes it atomically. fmu is held
// across snapshot+write so concurrent mutators can never persist snapshots out of order.
func (js *JSONFileStore) save(name string, build func() any) error {
	js.fmu.Lock()
	defer js.fmu.Unlock()
	js.MemStore.mu.Lock()
	data, err := json.MarshalIndent(build(), "", "  ")
	js.MemStore.mu.Unlock()
	if err != nil {
		return err
	}
	return js.writeFileAtomic(name, append(data, '\n'))
}

func (js *JSONFileStore) appendLine(name string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	js.fmu.Lock()
	defer js.fmu.Unlock()
	f, err := os.OpenFile(filepath.Join(js.dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (js *JSONFileStore) saveUsers() error {
	return js.save(fileUsers, func() any { return sortedVals(js.MemStore.users) })
}
func (js *JSONFileStore) saveTargets() error {
	return js.save(fileTargets, func() any { return sortedVals(js.MemStore.targets) })
}
func (js *JSONFileStore) saveAdapters() error {
	return js.save(fileAdapters, func() any { return sortedVals(js.MemStore.adapters) })
}
func (js *JSONFileStore) saveAdvisors() error {
	return js.save(fileAdvisors, func() any { return sortedVals(js.MemStore.advisors) })
}
func (js *JSONFileStore) saveAgentKeys() error {
	return js.save(fileAgentKeys, func() any { return sortedVals(js.MemStore.agentKeys) })
}
func (js *JSONFileStore) saveEntitlements() error {
	return js.save(fileEntitlements, func() any { return sortedVals(js.MemStore.entitlements) })
}
func (js *JSONFileStore) saveConsents() error {
	return js.save(fileConsents, func() any { return sortedVals(js.MemStore.consentReqs) })
}
func (js *JSONFileStore) saveOAuthClients() error {
	return js.save(fileOAuthClients, func() any { return sortedVals(js.MemStore.oauthClients) })
}
func (js *JSONFileStore) saveOAuthPending() error {
	return js.save(fileOAuthPending, func() any { return sortedVals(js.MemStore.oauthPending) })
}
func (js *JSONFileStore) saveChannelConns() error {
	return js.save(fileChannelConns, func() any { return sortedVals(js.MemStore.channelConns) })
}
func (js *JSONFileStore) saveChannelSettings() error {
	return js.save(fileChannelSets, func() any { return sortedVals(js.MemStore.channelSettings) })
}
func (js *JSONFileStore) saveSecrets() error {
	return js.save(fileSecrets, func() any { return js.MemStore.secrets })
}

// receiptFile maps a principal to its JSONL file. The name is display-only — the authoritative
// principal is inside every line — so lossy sanitizing can never mix chains on load.
func receiptFile(principal string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		default:
			return '_'
		}
	}, principal)
	if safe == "" {
		safe = "unknown"
	}
	return filepath.Join(dirReceipts, safe+".jsonl")
}

// --- mutators: delegate to MemStore, then mirror to disk on success ---

func (js *JSONFileStore) AppendReceipt(ctx context.Context, r *Receipt) error {
	if err := js.MemStore.AppendReceipt(ctx, r); err != nil {
		return err
	}
	return js.appendLine(receiptFile(r.Principal), r)
}

func (js *JSONFileStore) AppendEvent(ctx context.Context, e *Event) error {
	if err := js.MemStore.AppendEvent(ctx, e); err != nil {
		return err
	}
	return js.appendLine(fileEvents, e)
}

func (js *JSONFileStore) PutConsentRequest(ctx context.Context, r *ConsentRequest) error {
	if err := js.MemStore.PutConsentRequest(ctx, r); err != nil {
		return err
	}
	return js.saveConsents()
}

func (js *JSONFileStore) ExpireStaleConsentRequests(ctx context.Context, now int64) (int, error) {
	n, err := js.MemStore.ExpireStaleConsentRequests(ctx, now)
	if err != nil || n == 0 {
		return n, err
	}
	return n, js.saveConsents()
}

func (js *JSONFileStore) PutTarget(ctx context.Context, t *Target) error {
	if err := js.MemStore.PutTarget(ctx, t); err != nil {
		return err
	}
	return js.saveTargets()
}

func (js *JSONFileStore) PutAdapter(ctx context.Context, a *AdapterDoc) error {
	if err := js.MemStore.PutAdapter(ctx, a); err != nil {
		return err
	}
	return js.saveAdapters()
}

func (js *JSONFileStore) PutAdvisor(ctx context.Context, a *AdvisorDoc) error {
	if err := js.MemStore.PutAdvisor(ctx, a); err != nil {
		return err
	}
	return js.saveAdvisors()
}

func (js *JSONFileStore) PutOAuthClient(ctx context.Context, c *OAuthClient) error {
	if err := js.MemStore.PutOAuthClient(ctx, c); err != nil {
		return err
	}
	return js.saveOAuthClients()
}

func (js *JSONFileStore) PutOAuthPending(ctx context.Context, p *OAuthPending) error {
	if err := js.MemStore.PutOAuthPending(ctx, p); err != nil {
		return err
	}
	return js.saveOAuthPending()
}

func (js *JSONFileStore) TakeOAuthPending(ctx context.Context, state string) (*OAuthPending, error) {
	p, err := js.MemStore.TakeOAuthPending(ctx, state)
	if err != nil {
		return nil, err
	}
	return p, js.saveOAuthPending()
}

func (js *JSONFileStore) ExpireStalePending(ctx context.Context, olderThanUnix int64) (int, error) {
	n, err := js.MemStore.ExpireStalePending(ctx, olderThanUnix)
	if err != nil || n == 0 {
		return n, err
	}
	if err := js.saveOAuthPending(); err != nil {
		return n, err
	}
	return n, js.saveSecrets() // the sweep deletes the rows' sealed blobs too
}

func (js *JSONFileStore) PutUser(ctx context.Context, u *User) error {
	if err := js.MemStore.PutUser(ctx, u); err != nil {
		return err
	}
	return js.saveUsers()
}

func (js *JSONFileStore) PutEntitlement(ctx context.Context, e *Entitlement) error {
	if err := js.MemStore.PutEntitlement(ctx, e); err != nil {
		return err
	}
	return js.saveEntitlements()
}

func (js *JSONFileStore) PutAgentKey(ctx context.Context, k *AgentKey) error {
	if err := js.MemStore.PutAgentKey(ctx, k); err != nil {
		return err
	}
	return js.saveAgentKeys()
}

func (js *JSONFileStore) RevokeAgentKey(ctx context.Context, id string, at int64) error {
	if err := js.MemStore.RevokeAgentKey(ctx, id, at); err != nil {
		return err
	}
	return js.saveAgentKeys()
}

func (js *JSONFileStore) TouchAgentKey(ctx context.Context, id string, at int64) error {
	if err := js.MemStore.TouchAgentKey(ctx, id, at); err != nil {
		return err
	}
	return js.saveAgentKeys()
}

func (js *JSONFileStore) SetAgentKeyConsentChannels(ctx context.Context, id string, channels []string) error {
	if err := js.MemStore.SetAgentKeyConsentChannels(ctx, id, channels); err != nil {
		return err
	}
	return js.saveAgentKeys()
}

func (js *JSONFileStore) PutChannelConnection(ctx context.Context, c *ChannelConnection) error {
	if err := js.MemStore.PutChannelConnection(ctx, c); err != nil {
		return err
	}
	return js.saveChannelConns()
}

func (js *JSONFileStore) DeleteChannelConnection(ctx context.Context, userID, kind string) error {
	if err := js.MemStore.DeleteChannelConnection(ctx, userID, kind); err != nil {
		return err
	}
	return js.saveChannelConns()
}

func (js *JSONFileStore) PutChannelSetting(ctx context.Context, s *ChannelSetting) error {
	if err := js.MemStore.PutChannelSetting(ctx, s); err != nil {
		return err
	}
	return js.saveChannelSettings()
}

func (js *JSONFileStore) DeleteChannelSetting(ctx context.Context, kind string) error {
	if err := js.MemStore.DeleteChannelSetting(ctx, kind); err != nil {
		return err
	}
	return js.saveChannelSettings()
}

func (js *JSONFileStore) PutSecret(ctx context.Context, ref string, sealed []byte) error {
	if err := js.MemStore.PutSecret(ctx, ref, sealed); err != nil {
		return err
	}
	return js.saveSecrets()
}

func (js *JSONFileStore) DeleteSecret(ctx context.Context, ref string) error {
	if err := js.MemStore.DeleteSecret(ctx, ref); err != nil {
		return err
	}
	return js.saveSecrets()
}
