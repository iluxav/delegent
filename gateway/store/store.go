// Package store is Delegent's persistence seam. Everything stateful — live sessions (slip
// chains), the audit trail, pending escalations, and the fronted-vendor configuration —
// flows through the Store interface, so the broker and control plane hold no maps of their
// own. Two implementations ship here: MemStore (in-process, the dev default and the
// conformance reference) and JSONFileStore (durable local files, the single-operator
// backend). Other deployments plug their own backend into the same interface — the
// storetest conformance suite is the contract any implementation must pass.
//
// The load-bearing invariant lives here: a session persists the EXACT signed canonical bytes
// of every slip in its chain (SlipRow.Canonical), never a re-serialization. Rehydration
// verifies those bytes, so a tampered row fails exactly like a tampered wire slip. The
// projected columns (Effects, Scopes, ExpiresAt, BudgetRemaining) are a derived read-model
// for enforcement and listing — never the source of truth.
package store

import (
	"context"
	"encoding/json"
	"errors"
)

// ErrNotFound is returned by the Get* methods when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// SlipRow is one link of a chain as persisted: the exact bytes that were signed, plus the
// signature over them. Canonical == core.Canonical(body) at mint time; on load the body is
// recovered by unmarshalling Canonical and the signature is checked against these bytes.
type SlipRow struct {
	Canonical []byte `json:"canonical"`
	Sig       string `json:"sig"`
}

// Session is a live delegation: a slip chain (root-first), the holder's key sealed at rest,
// and a projection of the folded effective grant for querying and enforcement.
type Session struct {
	Handle       string
	Principal    string // owning principal, e.g. "root:alice"
	ParentHandle string // the session narrowed FROM; "" at a root
	Chain        []SlipRow
	SealedKey    []byte // holder private key, sealed by keyring.Sealer — never plaintext
	Pubkey       string // holder public key (hex); enough to augment/re-mint without unsealing

	// projection (folded effective values) — derived, indexed, not the source of truth
	Effects          uint
	Scopes           []string
	Ceiling          []string
	ExpiresAt        int64 // unix ms
	BudgetTotalC     int64 // cents; 0 with HasBudget=false means "no ceiling"
	BudgetRemainingC int64 // cents
	HasBudget        bool
	CreatedAt        int64 // unix ms
	RevokedAt        int64 // unix ms; 0 = not revoked
}

// LedgerEntry is one append-only debit written atomically alongside a successful Spend.
type LedgerEntry struct {
	Amount    int64 // cents, positive = debit
	Tool      string
	ReceiptID string
}

// Receipt is one audit record of an authority or access decision.
type Receipt struct {
	ID        string
	Principal string
	Handle    string
	Tool      string // the tool or action decided on ("request_access", "read_file", …)
	Decision  string // "grant" | "deny" | "flag"
	Reason    string
	Effect    string // rendered effect names, e.g. "read+write"
	Scopes    []string
	OverAsk   bool
	CreatedAt int64 // unix ms

	// PrevHash/Hash/Sig form a per-principal tamper-evident chain: Hash is computed over the
	// receipt's canonical fields folded with PrevHash (the principal's prior receipt hash), and
	// Sig is that Hash signed by the principal's ed25519 root key. Sig is empty when a receipt
	// was recorded unsigned (fail-soft: root key unavailable at mint).
	PrevHash string // hash of the principal's previous receipt ("" at the chain root)
	Hash     string // H(canonical(fields) ‖ PrevHash)
	Sig      string // ed25519 signature over Hash by the principal's root key ("" = unsigned)
}

// ReceiptFilter narrows a ListReceipts query. Zero-value fields are ignored.
type ReceiptFilter struct {
	Principal string
	Handle    string
	Limit     int // 0 = no limit
}

// Escalation is a parked authority request awaiting an ancestor's approval.
type Escalation struct {
	ID           string
	ChildHandle  string // the requester short on authority
	ParentHandle string // the ancestor that holds it and must approve
	Scopes       []string
	Reason       string
	Status       string // "pending" | "approved" | "denied"
	CreatedAt    int64
	ResolvedAt   int64
}

// ConsentRequest is a DURABLE console-consent ask: a client that can only consent in the web
// console parks one, the guarded call returns "pending — retry shortly" after a short sync
// window, and a human approves/denies it ANYTIME from the console. Unlike the in-memory
// pending nonce (gateway.pendingConsent), this row outlives the blocked call, so approval can
// land long after the agent gave up and retried. Status is one of
// pending|approved|denied|expired|cancelled (cancelled = the agent withdrew the call
// before any human decided).
type ConsentRequest struct {
	ID        string
	TargetID  string
	Principal string   // the target owner the request is scoped to (the console operator)
	AgentName string   // the requesting agent's display identity, resolved at park time
	Scopes    []string // scopes asked for
	Reason    string
	// Headline and Intent are the legible display the in-chat dialogs render (action + risk
	// markers, and the agent's declared why). Persisted so every LATER surface — the console
	// approvals card, telegram notices — shows exactly what the dialog would have. Empty on
	// rows that predate this field or asks with no originating tool call (fail-soft).
	Headline      string
	Intent        string
	Status        string   // pending | approved | denied | expired
	DecidedScopes []string // scopes actually granted on approval (subset of Scopes)
	TTLMinutes    int      // grant lifetime chosen at approval
	BudgetUSD     float64  // spend ceiling chosen at approval
	CreatedAt     int64    // unix ms
	ExpiresAt     int64    // unix ms; a pending row past this is swept to "expired"
	ResolvedAt    int64    // unix ms; 0 while pending
}

// Event types for the operator-facing activity log (store.Event.Type).
const (
	EventConnection          = "connection"
	EventToolCall            = "tool_call"
	EventToolResponse        = "tool_response"
	EventPermissionRequested = "permission_requested"
	EventPermissionGranted   = "permission_granted"
	EventPermissionDenied    = "permission_denied"
	EventError               = "error"
	EventDisconnected        = "disconnected"
)

// Event is one row of the durable, operator-facing ACTIVITY LOG: an append-only stream of what
// an agent connection did (connected, called a tool, was granted/denied access, errored). It is
// distinct from Receipt (the authority-decision audit record): the activity log carries the
// caller's identity (key_prefix/key_name, resolved IP, client), the tool params/results, and
// every connection/response event, so the console can render a filterable timeline. key_name is
// the DURABLE aggregation key — it survives key rotation, so a filter by key_name groups every
// event a named key ever produced.
type Event struct {
	ID            string
	CreatedAt     int64  // unix ms
	Type          string // connection | tool_call | tool_response | permission_* | error
	UserID        string
	KeyPrefix     string
	KeyName       string
	TargetID      string
	SessionHandle string
	AgentName     string
	Tool          string
	Intent        string // the agent's self-declared _delegent_intent (WHY); recorded on every vendor call, prompted or not
	Scopes        []string
	Decision      string
	Reason        string
	ClientName    string
	ClientVersion string
	RemoteIP      string
	Params        json.RawMessage
	Result        json.RawMessage
	Error         string
}

// EventFilter narrows a ListEvents query. Every field is optional — a zero value is ignored.
// Results are newest-first. Limit defaults to 200 and is capped at 1000.
type EventFilter struct {
	UserID    string
	KeyName   string
	KeyPrefix string
	Type      string
	TargetID  string
	Tool      string
	Decision  string
	Since     int64 // unix ms; 0 = no lower bound
	Until     int64 // unix ms; 0 = no upper bound
	Limit     int   // 0 = default 200; capped at 1000
}

// EventLimitDefault / EventLimitMax bound a ListEvents page.
const (
	EventLimitDefault = 200
	EventLimitMax     = 1000
)

// --- configuration (was adapters/<vendor>/*.json + DELEGENT_* env) ---

// Target is a configured 3rd-party MCP or REST endpoint Delegent fronts.
type Target struct {
	ID            string
	Name          string
	Kind          string // "mcp" | "rest"
	Endpoint      string // upstream URL
	CredentialRef string // pointer into SecretStore; NEVER the raw secret
	// CredentialKind selects how CredentialRef is interpreted and injected.
	// "static_bearer" (default) = the sealed value is a bare token set as Bearer.
	// "oauth2" = the sealed value is a JSON TokenSet, refreshed before injection.
	// "query_param" = the sealed value is appended to the endpoint as a query arg.
	CredentialKind string
	AdapterID      string
	AdvisorID      string
	Owner          string // user id that owns/operates this target
	Enabled        bool
}

// OAuthClient is the per-target OAuth 2.1 client registration: the vendor's authorization and
// token endpoints, our client_id, an optional pointer to the sealed client_secret (empty for
// public clients), the requested scopes (space-delimited), and the redirect URI. It is keyed by
// TargetID; the obtained token lives separately, sealed under the target's CredentialRef.
type OAuthClient struct {
	TargetID, AuthEndpoint, TokenEndpoint, ClientID, ClientSecretRef, Scopes, RedirectURI string
}

// OAuthFlow is durable state for one in-flight authorization-code + PKCE exchange: the opaque
// State the vendor echoes back on the callback maps to the CodeVerifier that proves possession.
// It lives in a table (not memory) so a gateway restart or a second instance can complete the
// callback. It is SINGLE-USE: TakeOAuthFlow reads-and-deletes atomically so a state is consumed
// exactly once (prevents replay).
type OAuthFlow struct {
	State, TargetID, CodeVerifier string
	CreatedAt                     int64 // unix seconds
}

// OAuthPending is a TARGET-LESS slot for an OAuth-first create-target flow: the operator
// connects a vendor via OAuth and obtains a token BEFORE the target exists. The token + client
// config live here keyed by the OAuth State, and get promoted onto a target only when the
// operator saves. There is deliberately no FK to targets. ClientSecretRef is empty for public
// clients; TokenRef is empty until the callback seals the obtained TokenSet and updates the row.
type OAuthPending struct {
	State, AuthEndpoint, TokenEndpoint, ClientID, ClientSecretRef, Scopes, RedirectURI, CodeVerifier, TokenRef string
	CreatedAt                                                                                                  int64 // unix seconds
}

// AdapterDoc is the exact adapter classification document core/loader parses (stored JSONB).
type AdapterDoc struct {
	ID   string
	Name string
	Doc  json.RawMessage
}

// AdvisorDoc is the exact advisor document core/loader parses (stored JSONB).
type AdvisorDoc struct {
	ID   string
	Name string
	Doc  json.RawMessage
}

// User is the operator identity: our own record (id usr_…) linked to an external auth id, with
// ONE root signing key (public hex + private key sealed with the master key). A user owns many
// targets; its ceiling on each is an Entitlement. The slip issuer (a "principal", in crypto
// terms) IS a user id.
type User struct {
	ID         string // usr_…
	ExternalID string // external auth-provider id in hosted deployments; a fixed label locally; "" for seeded/system users
	Email      string
	Name       string
	Pubkey     string // ed25519 public key, hex
	SealedKey  []byte // ed25519 private key, sealed by keyring.Sealer — never plaintext
	CreatedAt  int64
	UpdatedAt  int64
}

// Entitlement is a user's scope ceiling on one target. Scopes is the full granted universe
// (kept in sync with the target's classification); Disabled is the operator's explicit
// opt-outs within it. Enforcement must use Effective(), never Scopes directly — keeping the
// two lists separate means a re-classification can grow Scopes without silently resurrecting
// a scope the operator switched off.
type Entitlement struct {
	UserID   string
	TargetID string
	Scopes   []string
	Disabled []string
}

// Effective returns Scopes minus Disabled — the scopes enforcement may actually grant.
func (e *Entitlement) Effective() []string {
	if len(e.Disabled) == 0 {
		return append([]string(nil), e.Scopes...)
	}
	off := map[string]bool{}
	for _, s := range e.Disabled {
		off[s] = true
	}
	out := []string{}
	for _, s := range e.Scopes {
		if !off[s] {
			out = append(out, s)
		}
	}
	return out
}

// AgentKey authenticates a user to the gateway. Only Hash (sha256 of the plaintext) is stored;
// the plaintext is shown once at creation and never again. One key covers all the user's targets.
type AgentKey struct {
	ID         string // akey_…
	UserID     string
	Hash       []byte // sha256 of the full "dgk_…" token
	Prefix     string // display only
	Name       string
	CreatedAt  int64
	LastUsedAt int64 // 0 = never
	RevokedAt  int64 // 0 = active
	// ConsentChannels is this key's ordered consent-channel policy ("elicitation" | "widget" |
	// "console"): how a human approves requests from the harness holding this key. Empty = auto
	// (capability order). The gateway always falls back to the web console after the list.
	ConsentChannels []string
}

// ChannelConnection binds a user to an out-of-band approval surface (a telegram chat; later
// slack, …). One connection per (user, kind); Address is the channel-native destination (e.g.
// the telegram chat id) and Label a display-only handle (e.g. "@name").
type ChannelConnection struct {
	UserID    string
	Kind      string // "telegram"
	Address   string
	Label     string
	CreatedAt int64 // unix ms
}

// ChannelSetting is deployment-level configuration for one out-of-band channel kind ("telegram":
// {"bot_username": …}; later slack). The channel's SECRET (bot token) never lives here — it is
// sealed in the secret store (ref "channel:<kind>:token"); Settings holds only display-safe JSON.
type ChannelSetting struct {
	Kind      string
	Settings  json.RawMessage
	UpdatedAt int64 // unix ms
}

// ChannelLinkToken is a single-use, TTL'd handshake nonce for establishing a
// ChannelConnection: minted by the console, redeemed by the channel side (e.g. the telegram
// bot receiving "/start <token>").
type ChannelLinkToken struct {
	Token     string
	UserID    string
	Kind      string
	ExpiresAt int64 // unix ms
	CreatedAt int64 // unix ms
}

// Store is the persistence port. All methods take a context and are safe for concurrent use.
type Store interface {
	// sessions
	PutSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, handle string) (*Session, error)
	ListSessions(ctx context.Context, principal string) ([]*Session, error)

	// atomic spend: debits BudgetRemainingC iff it stays >= 0, appends the ledger entry, and
	// returns the new remaining. Returns ErrInsufficientBudget if the debit would overdraw.
	Spend(ctx context.Context, handle string, amount int64, entry LedgerEntry) (remaining int64, err error)

	// receipts
	AppendReceipt(ctx context.Context, r *Receipt) error
	ListReceipts(ctx context.Context, f ReceiptFilter) ([]*Receipt, error)
	// LastReceiptHash returns the Hash of the most recent receipt for principal, or "" if none exist.
	LastReceiptHash(ctx context.Context, principal string) (string, error)

	// activity log (operator-facing event stream; distinct from receipts)
	AppendEvent(ctx context.Context, e *Event) error
	ListEvents(ctx context.Context, f EventFilter) ([]*Event, error)

	// escalations
	PutEscalation(ctx context.Context, e *Escalation) error
	GetEscalation(ctx context.Context, id string) (*Escalation, error)
	ListPendingEscalations(ctx context.Context, parentHandle string) ([]*Escalation, error)

	// durable console consent requests
	PutConsentRequest(ctx context.Context, r *ConsentRequest) error // upsert by id
	GetConsentRequest(ctx context.Context, id string) (*ConsentRequest, error)
	// ListConsentRequests returns requests for principal (empty = all), pending-first then
	// newest-first. includeResolved=false returns only status=pending.
	ListConsentRequests(ctx context.Context, principal string, includeResolved bool) ([]*ConsentRequest, error)
	// ExpireStaleConsentRequests flips every pending row past its ExpiresAt to "expired"
	// (stamping ResolvedAt=now) and returns how many it swept.
	ExpireStaleConsentRequests(ctx context.Context, now int64) (int, error)

	// configuration
	GetTarget(ctx context.Context, id string) (*Target, error)
	ListTargets(ctx context.Context) ([]*Target, error)
	PutTarget(ctx context.Context, t *Target) error
	GetAdapter(ctx context.Context, id string) (*AdapterDoc, error)
	PutAdapter(ctx context.Context, a *AdapterDoc) error
	GetAdvisor(ctx context.Context, id string) (*AdvisorDoc, error)
	PutAdvisor(ctx context.Context, a *AdvisorDoc) error
	// oauth clients (per-target OAuth 2.1 registration; keyed by target id)
	GetOAuthClient(ctx context.Context, targetID string) (*OAuthClient, error)
	PutOAuthClient(ctx context.Context, c *OAuthClient) error
	// oauth flows (in-flight PKCE state; single-use)
	PutOAuthFlow(ctx context.Context, f *OAuthFlow) error
	TakeOAuthFlow(ctx context.Context, state string) (*OAuthFlow, error) // single-use: read-and-delete
	// target-less pending OAuth (OAuth-first create-target flow; keyed by state)
	PutOAuthPending(ctx context.Context, p *OAuthPending) error                // upsert on state
	GetOAuthPending(ctx context.Context, state string) (*OAuthPending, error)  // read (does NOT delete — the callback updates token_ref, then the wizard reads it, then save consumes it)
	TakeOAuthPending(ctx context.Context, state string) (*OAuthPending, error) // read-and-delete (single-use, called at save/promotion time)
	// ExpireStalePending reaps abandoned pending rows whose created_at (unix seconds) is older
	// than olderThanUnix, deleting the row AND its associated sealed token/client-secret blobs,
	// and returns how many rows it swept.
	ExpireStalePending(ctx context.Context, olderThanUnix int64) (int, error)
	// users (operator identity + root key)
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByExternal(ctx context.Context, externalID string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)
	PutUser(ctx context.Context, u *User) error

	// entitlements (user × target → scopes)
	GetEntitlement(ctx context.Context, userID, targetID string) (*Entitlement, error)
	ListEntitlementsForTarget(ctx context.Context, targetID string) ([]*Entitlement, error)
	ListEntitlementsForUser(ctx context.Context, userID string) ([]*Entitlement, error)
	PutEntitlement(ctx context.Context, e *Entitlement) error

	// agent keys (gateway authentication)
	PutAgentKey(ctx context.Context, k *AgentKey) error // create-only: keys are never rewritten, only revoked (a duplicate id is an error)
	GetAgentKey(ctx context.Context, id string) (*AgentKey, error)
	GetAgentKeyByHash(ctx context.Context, hash []byte) (*AgentKey, error)
	ListAgentKeys(ctx context.Context, userID string) ([]*AgentKey, error)
	RevokeAgentKey(ctx context.Context, id string, at int64) error
	TouchAgentKey(ctx context.Context, id string, at int64) error
	// SetAgentKeyConsentChannels replaces the key's consent-channel policy (nil/empty = auto).
	// The only mutable key field besides revocation/touch — keys are otherwise create-only.
	SetAgentKeyConsentChannels(ctx context.Context, id string, channels []string) error

	// channel connections (user × kind → out-of-band approval destination)
	PutChannelConnection(ctx context.Context, c *ChannelConnection) error // upsert on (user, kind)
	GetChannelConnection(ctx context.Context, userID, kind string) (*ChannelConnection, error)
	ListChannelConnections(ctx context.Context, userID string) ([]*ChannelConnection, error)
	DeleteChannelConnection(ctx context.Context, userID, kind string) error
	// channel link tokens (single-use; Take consumes, and an expired token is ErrNotFound)
	PutChannelLinkToken(ctx context.Context, t *ChannelLinkToken) error
	TakeChannelLinkToken(ctx context.Context, token string, now int64) (*ChannelLinkToken, error)
	// channel settings (deployment-level, one row per kind; secrets live in the secret store)
	PutChannelSetting(ctx context.Context, s *ChannelSetting) error // upsert on kind
	GetChannelSetting(ctx context.Context, kind string) (*ChannelSetting, error)
	DeleteChannelSetting(ctx context.Context, kind string) error

	// sealed secrets (the sealed bytes are opaque to the store — sealing is the caller's job)
	GetSecret(ctx context.Context, ref string) ([]byte, error)
	PutSecret(ctx context.Context, ref string, sealed []byte) error
	DeleteSecret(ctx context.Context, ref string) error // idempotent: deleting a nonexistent ref is a no-op (nil)

	Close() error
}

// ErrInsufficientBudget is returned by Spend when the debit would overdraw the session.
var ErrInsufficientBudget = errors.New("store: insufficient budget")
