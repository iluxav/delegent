package main

// Client configuration snippets and the dedicated agent-key management page.
// A key's plaintext exists only at mint time, so the snippets carry a placeholder until you
// mint or roll one on the Keys page — then they are rendered with the real key, once.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"delegent.dev/gateway"
)

// hermesYAML renders a Hermes config.yaml mcp_servers entry: the transport (url, or command
// with args ["stdio"]), optional headers, optional env. Values are double-quoted so paths and
// keys survive YAML parsing verbatim.
func hermesYAML(transport, headers, env map[string]string) string {
	q := func(s string) string { return strconv.Quote(s) }
	var b strings.Builder
	b.WriteString("mcp_servers:\n  delegent:\n")
	if u, ok := transport["url"]; ok {
		b.WriteString("    url: " + q(u) + "\n")
	}
	if c, ok := transport["command"]; ok {
		b.WriteString("    command: " + q(c) + "\n    args: [\"stdio\"]\n")
	}
	if len(headers) > 0 {
		b.WriteString("    headers:\n")
		for _, k := range sortedKeys(headers) {
			b.WriteString("      " + k + ": " + q(headers[k]) + "\n")
		}
	}
	if len(env) > 0 {
		b.WriteString("    env:\n")
		for _, k := range sortedKeys(env) {
			b.WriteString("      " + k + ": " + q(env[k]) + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// keyPlaceholder stands in for a key the dashboard cannot know (every stored key is hashed).
const keyPlaceholder = "dgk_…"

type keyView struct {
	ID, Name, Prefix, LastUsed string
	Revoked                    bool
	// Channels is the key's consent-channel policy as the joined preset value the form posts
	// back; Hint explains what that order means. Both come from the SAME presets the terminal
	// dashboard offers, so the two surfaces cannot disagree about what a policy means.
	Channels, Hint string
	// ViaOAuth marks a connection the operator approved in a browser rather than a key they
	// copied into a config file. Client is the agent that registered for it.
	ViaOAuth bool
	Client   string
	// Agent names the A2A target this key was issued to (the key that agent uses when it calls
	// other targets through the gateway); empty for a person's harness.
	Agent string
}

// channelPreset is one row of the consent-channel picker.
type channelPreset struct{ Value, Label, Hint string }

// channelPresets renders the shared consentPresets for a <select>.
func channelPresets() []channelPreset {
	out := make([]channelPreset, 0, len(consentPresets))
	for _, p := range consentPresets {
		out = append(out, channelPreset{Value: strings.Join(p.channels, ","), Label: p.label, Hint: presetHint(p.channels)})
	}
	return out
}

// snippet is one client's way in. The primary form is the REMOTE url — with the gateway's own
// OAuth, the agent signs in through the dashboard and no key is involved at all. Alt* is the
// fallback for a client you would rather launch locally with a minted key.
type snippet struct {
	ID       string // stable client id
	Label    string // client name
	Category string // short description shown in the client picker
	File     string // where the primary form goes
	Note     string
	Cmd      string // a one-line CLI that does the whole thing, when the client has one
	JSON     string // the remote form: url only

	AltFile, AltNote, AltJSON string // the agent-key form (stdio)
}

type connectView struct {
	Presets  []channelPreset
	Keys     []keyView
	Snippets []snippet
	Minted   string // plaintext of a key just minted or rolled — shown exactly once
	MintName string
	// Agents lists the registered A2A targets, so a key can be issued to one of them.
	Agents      []string
	Notice      string
	Error       string
	Placeholder bool // the snippets carry the placeholder, not a real key
}

// --- snippet shapes, one struct per client family so field ORDER is what you would type ---

type stdioServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

type vscodeServer struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

type httpServer struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
}

type openaiTool struct {
	Type            string            `json:"type"`
	ServerLabel     string            `json:"server_label"`
	ServerURL       string            `json:"server_url"`
	Headers         map[string]string `json:"headers,omitempty"`
	RequireApproval string            `json:"require_approval"`
}

func mustJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// delegentCommand is what a client should launch: the bare name when it is on PATH (portable
// across machines), otherwise this build's absolute path.
func delegentCommand() string {
	if _, err := exec.LookPath("delegent"); err == nil {
		return "delegent"
	}
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	return "delegent"
}

// defaultHome mirrors homeFlag's default, so the snippet only pins DELEGENT_HOME when this
// instance is somewhere unusual.
func defaultHome() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".delegent")
	}
	return ".delegent"
}

// reachableAddr turns a bind address into one a client can actually dial.
func reachableAddr(addr string) string {
	if strings.HasPrefix(addr, "0.0.0.0:") {
		return "127.0.0.1:" + strings.TrimPrefix(addr, "0.0.0.0:")
	}
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	return addr
}

// buildSnippets renders every client's config. The remote form needs no key: the agent hits
// /mcp, gets a 401 pointing at this gateway's own OAuth metadata, and signs in with the
// dashboard login. key is only baked into the stdio fallbacks.
func (w *webApp) buildSnippets(key string) []snippet {
	env := map[string]string{"DELEGENT_AGENT_KEY": key}
	if w.e.home != defaultHome() {
		env["DELEGENT_HOME"] = w.e.home
	}
	cmd := delegentCommand()
	stdio := stdioServer{Command: cmd, Args: []string{"stdio"}, Env: env}
	url := "http://" + reachableAddr(w.e.cfg.ListenAddr) + "/mcp"

	mcpServers := func(v any) string {
		return mustJSON(map[string]any{"mcpServers": map[string]any{"delegent": v}})
	}
	remote := mcpServers(httpServer{URL: url})
	signInNote := "No key needed. The agent asks for a token, Delegent sends you to its own sign-in page, and you approve with your dashboard login."

	return []snippet{
		{
			ID: "claude-code", Label: "Claude Code", Category: "Terminal",
			File:    "one command, from anywhere",
			Cmd:     "claude mcp add --transport http delegent " + url,
			Note:    signInNote + " Run /mcp in Claude Code afterwards and pick Authenticate.",
			JSON:    remote,
			AltFile: ".mcp.json in your project, or ~/.claude.json",
			AltNote: "Launches delegent locally instead, authenticating with a minted key.",
			AltJSON: mcpServers(stdio),
		},
		{
			ID: "claude-desktop", Label: "Claude Desktop", Category: "Desktop app",
			File:    "Settings → Connectors → Add custom connector",
			Cmd:     url,
			Note:    signInNote + " Paste the URL above as a custom connector; Claude Desktop opens the sign-in itself.",
			JSON:    remote,
			AltFile: "claude_desktop_config.json",
			AltNote: "The local-process form. Restart Claude Desktop after saving.",
			AltJSON: mcpServers(stdio),
		},
		{
			ID: "cursor", Label: "Cursor", Category: "Code editor",
			File:    "~/.cursor/mcp.json, or .cursor/mcp.json in the project",
			Note:    signInNote,
			JSON:    remote,
			AltFile: "the same file, launching delegent locally",
			AltNote: "Uses a minted key instead of signing in.",
			AltJSON: mcpServers(stdio),
		},
		{
			ID: "vscode", Label: "VS Code", Category: "Code editor",
			File:    ".vscode/mcp.json",
			Note:    signInNote + " VS Code names the map \"servers\" and wants an explicit type.",
			JSON:    mustJSON(map[string]any{"servers": map[string]any{"delegent": map[string]any{"type": "http", "url": url}}}),
			AltFile: "the same file, launching delegent locally",
			AltNote: "Uses a minted key instead of signing in.",
			AltJSON: mustJSON(map[string]any{"servers": map[string]any{"delegent": vscodeServer{
				Type: "stdio", Command: cmd, Args: []string{"stdio"}, Env: env,
			}}}),
		},
		{
			ID: "hermes", Label: "Hermes", Category: "Terminal",
			File:    "one command, from anywhere — paste a minted key when it asks",
			Cmd:     "hermes mcp add delegent --url " + url + " --auth header",
			Note:    "Hermes stores the key in ~/.hermes/.env and references it from config.yaml. Use --auth oauth instead to sign in through Delegent with no key. Hermes has no consent dialog of its own, so approvals land in this dashboard's Alerts (or telegram / the CLI).",
			JSON:    hermesYAML(map[string]string{"url": url}, map[string]string{"Authorization": "Bearer " + key}, nil),
			AltFile: "~/.hermes/config.yaml, launching delegent locally",
			AltNote: "The local-process form, with a minted key.",
			AltJSON: hermesYAML(map[string]string{"command": cmd}, nil, env),
		},
		{
			ID: "pi", Label: "Pi", Category: "Terminal",
			File:    "once: install the MCP adapter (Pi has no built-in MCP), then restart Pi",
			Cmd:     "pi install npm:pi-mcp-adapter",
			Note:    "Then save the configuration as ~/.config/mcp/mcp.json (every project) or .mcp.json in the project. The adapter adds one proxy tool that discovers Delegent's tools on demand; /mcp inside Pi lists the servers. Delegent's consent dialog appears in Pi's own prompts (the adapter supports elicitation).",
			JSON:    mcpServers(map[string]any{"url": url, "headers": map[string]string{"Authorization": "Bearer " + key}}),
			AltFile: "the same file, launching delegent locally",
			AltNote: "The local-process form, with a minted key.",
			AltJSON: mcpServers(stdio),
		},
		{
			ID: "openai", Label: "ChatGPT / OpenAI", Category: "Chat & API",
			File: "an MCP tool on the Responses API",
			Note: "Remote MCP, so OpenAI's servers must reach this gateway — put it behind a public URL (a tunnel) and swap the host. It will sign in through Delegent the same way.",
			JSON: mustJSON(openaiTool{
				Type: "mcp", ServerLabel: "delegent", ServerURL: url, RequireApproval: "never",
			}),
			AltFile: "with a minted key instead of signing in",
			AltNote: "Skips the OAuth round trip by presenting a key directly.",
			AltJSON: mustJSON(openaiTool{
				Type: "mcp", ServerLabel: "delegent", ServerURL: url,
				Headers: map[string]string{"Authorization": "Bearer " + key}, RequireApproval: "never",
			}),
		},
		{
			ID: "http", Label: "Any HTTP client", Category: "Custom integration",
			File:    "streamable HTTP",
			Note:    "An unauthenticated call answers 401 with WWW-Authenticate pointing at this gateway's OAuth metadata. /mcp/<server> instead of /mcp pins a single server.",
			JSON:    remote,
			AltFile: "with a bearer key",
			AltNote: "For a client that does not speak OAuth.",
			AltJSON: mcpServers(httpServer{URL: url, Headers: map[string]string{"Authorization": "Bearer " + key}}),
		},
	}
}

// connectView assembles key management and client snippets. Plaintext is non-empty only
// right after a mint or roll.
func (w *webApp) connectView(r *http.Request, plaintext string) connectView {
	key := plaintext
	v := connectView{Minted: plaintext}
	if key == "" {
		key, v.Placeholder = keyPlaceholder, true
	}
	v.Snippets = w.buildSnippets(key)

	keys, err := w.e.st.ListAgentKeys(r.Context(), w.e.operator)
	if err != nil {
		v.Error = err.Error()
		return v
	}
	v.Presets = channelPresets()
	for _, k := range keys {
		v.Keys = append(v.Keys, keyView{
			ID: k.ID, Name: k.Name, Prefix: k.Prefix, Revoked: k.RevokedAt != 0, LastUsed: lastUsed(k.LastUsedAt),
			Channels: strings.Join(k.ConsentChannels, ","), Hint: presetHint(k.ConsentChannels),
			ViaOAuth: k.OAuthClientID != "", Client: w.clientName(k.OAuthClientID),
			Agent: k.AgentTargetID,
		})
	}
	if ts, err := w.e.st.ListTargets(r.Context()); err == nil {
		for _, t := range ts {
			if t.Kind == gateway.TargetKindA2A {
				v.Agents = append(v.Agents, t.ID)
			}
		}
		sort.Strings(v.Agents)
	}
	return v
}

func lastUsed(ms int64) string {
	if ms == 0 {
		return "never used"
	}
	d := time.Since(time.UnixMilli(ms))
	switch {
	case d < time.Minute:
		return "used just now"
	case d < time.Hour:
		return fmt.Sprintf("used %dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("used %dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("used %dd ago", int(d.Hours()/24))
	}
}

// --- handlers ---

func (w *webApp) connectPane(rw http.ResponseWriter, r *http.Request) {
	w.render(rw, "connect", w.connectView(r, ""))
}

func (w *webApp) keysPage(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")
	w.page(rw, r, "", "keysPage", w.connectView(r, ""))
}

// Key changes replace the management page and refresh client snippets out of band.
// Plaintext is confined to the mint/rotate response; reloads only see placeholders.
func (w *webApp) renderKeys(rw http.ResponseWriter, r *http.Request, v connectView) {
	rw.Header().Set("Cache-Control", "no-store")
	if v.Error != "" {
		v.MintName = r.FormValue("name")
	}
	if r.Header.Get("HX-Request") != "" && r.Header.Get("HX-Boosted") == "" {
		rw.Header().Set("HX-Push-Url", "/keys")
		w.render(rw, "keysResult", v)
		return
	}
	w.render(rw, "page", pageData{
		Targets: w.targetRows(r), User: w.auth.username(), Version: version,
		Main: w.partial("keysPage", v), Connect: w.partial("connect", v),
	})
}

func (w *webApp) mintKey(rw http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	agent := strings.TrimSpace(r.FormValue("agent"))
	if agent != "" {
		// Issued to an agent: it must be a registered A2A target; the name defaults to it.
		if t, err := w.e.st.GetTarget(r.Context(), agent); err != nil || t.Kind != gateway.TargetKindA2A {
			v := w.connectView(r, "")
			v.Error = fmt.Sprintf("%q is not a registered agent", agent)
			w.renderKeys(rw, r, v)
			return
		}
		if name == "" {
			name = "agent:" + agent
		}
	}
	if name == "" {
		v := w.connectView(r, "")
		v.Error = "give the key a name — events and rolls are tracked by it"
		w.renderKeys(rw, r, v)
		return
	}
	a := &adminEnv{e: w.e, reg: w.reg}
	row, plaintext, err := a.mintAgent(r, name, agent)
	if err != nil {
		v := w.connectView(r, "")
		v.Error = err.Error()
		w.renderKeys(rw, r, v)
		return
	}
	v := w.connectView(r, plaintext)
	v.Notice = fmt.Sprintf("Key %q minted (%s). Copy it now — it is never shown again.", name, row.Prefix)
	w.renderKeys(rw, r, v)
}

func (w *webApp) revokeKey(rw http.ResponseWriter, r *http.Request) {
	if err := w.e.st.RevokeAgentKey(r.Context(), r.PathValue("id"), nowMillis()); err != nil {
		v := w.connectView(r, "")
		v.Error = err.Error()
		w.renderKeys(rw, r, v)
		return
	}
	v := w.connectView(r, "")
	v.Notice = "Key revoked. An agent holding it is refused at its next connection."
	w.renderKeys(rw, r, v)
}

// rollKey mints a replacement under the same name, then revokes the old one — mint first, so
// a roll can never leave you with no working key.
func (w *webApp) rollKey(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	old, err := w.e.st.GetAgentKey(ctx, r.PathValue("id"))
	if err != nil {
		v := w.connectView(r, "")
		v.Error = "no such key"
		w.renderKeys(rw, r, v)
		return
	}
	a := &adminEnv{e: w.e, reg: w.reg}
	row, plaintext, err := a.mint(r, old.Name)
	if err != nil {
		v := w.connectView(r, "")
		v.Error = err.Error()
		w.renderKeys(rw, r, v)
		return
	}
	if err := w.e.st.RevokeAgentKey(ctx, old.ID, nowMillis()); err != nil {
		v := w.connectView(r, plaintext)
		v.Error = fmt.Sprintf("new key minted (%s) but revoking the old one failed: %v", row.Prefix, err)
		w.renderKeys(rw, r, v)
		return
	}
	v := w.connectView(r, plaintext)
	v.Notice = fmt.Sprintf("Rolled %q — the old key is revoked. Copy the new one now.", old.Name)
	w.renderKeys(rw, r, v)
}

// setKeyChannels stores which channel this key's agent is asked through. The console is always
// the implicit final fallback, so a policy can never leave a request with nowhere to go.
//
// It applies to the agent's NEXT connection: the policy rides in on the verified token and is
// captured once per MCP session, so a client that is already connected keeps the old routing
// until it reconnects.
func (w *webApp) setKeyChannels(rw http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.FormValue("channels"))
	var channels []string
	if raw != "" {
		channels = strings.Split(raw, ",")
	}
	if err := validateChannels(channels); err != nil {
		v := w.connectView(r, "")
		v.Error = err.Error()
		w.renderKeys(rw, r, v)
		return
	}
	if err := w.e.st.SetAgentKeyConsentChannels(r.Context(), r.PathValue("id"), channels); err != nil {
		v := w.connectView(r, "")
		v.Error = err.Error()
		w.renderKeys(rw, r, v)
		return
	}
	v := w.connectView(r, "")
	v.Notice = "Consent channel set to " + presetLabel(channels) + ". It applies the next time that agent connects."
	w.renderKeys(rw, r, v)
}

// clientName resolves a registered agent's display name, falling back to the id if the
// registration has since been forgotten.
func (w *webApp) clientName(clientID string) string {
	if clientID == "" {
		return ""
	}
	if c, ok := w.prov.client(clientID); ok && c.Name != "" {
		return c.Name
	}
	return clientID
}
