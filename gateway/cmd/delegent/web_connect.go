package main

// The connect pane: agent keys, and the config snippet to paste into each kind of AI client.
// A key's plaintext exists only at mint time, so the snippets carry a placeholder until you
// mint or roll one here — then they are rendered with the real key, once.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

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
	ID    string // tab id
	Label string // tab label
	File  string // where the primary form goes
	Note  string
	Cmd   string // a one-line CLI that does the whole thing, when the client has one
	JSON  string // the remote form: url only

	AltFile, AltNote, AltJSON string // the agent-key form (stdio)
}

type connectView struct {
	Presets     []channelPreset
	Keys        []keyView
	Snippets    []snippet
	Minted      string // plaintext of a key just minted or rolled — shown exactly once
	MintName    string
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
			ID: "claude-code", Label: "Claude Code",
			File:    "one command, from anywhere",
			Cmd:     "claude mcp add --transport http delegent " + url,
			Note:    signInNote + " Run /mcp in Claude Code afterwards and pick Authenticate.",
			JSON:    remote,
			AltFile: ".mcp.json in your project, or ~/.claude.json",
			AltNote: "Launches delegent locally instead, authenticating with a minted key.",
			AltJSON: mcpServers(stdio),
		},
		{
			ID: "claude-desktop", Label: "Claude Desktop",
			File:    "Settings → Connectors → Add custom connector",
			Cmd:     url,
			Note:    signInNote + " Paste the URL above as a custom connector; Claude Desktop opens the sign-in itself.",
			JSON:    remote,
			AltFile: "claude_desktop_config.json",
			AltNote: "The local-process form. Restart Claude Desktop after saving.",
			AltJSON: mcpServers(stdio),
		},
		{
			ID: "cursor", Label: "Cursor",
			File:    "~/.cursor/mcp.json, or .cursor/mcp.json in the project",
			Note:    signInNote,
			JSON:    remote,
			AltFile: "the same file, launching delegent locally",
			AltNote: "Uses a minted key instead of signing in.",
			AltJSON: mcpServers(stdio),
		},
		{
			ID: "vscode", Label: "VS Code",
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
			ID: "openai", Label: "ChatGPT / OpenAI",
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
			ID: "http", Label: "Any HTTP client",
			File:    "streamable HTTP",
			Note:    "An unauthenticated call answers 401 with WWW-Authenticate pointing at this gateway's OAuth metadata. /mcp/<server> instead of /mcp pins a single server.",
			JSON:    remote,
			AltFile: "with a bearer key",
			AltNote: "For a client that does not speak OAuth.",
			AltJSON: mcpServers(httpServer{URL: url, Headers: map[string]string{"Authorization": "Bearer " + key}}),
		},
	}
}

// connectView assembles the pane. plaintext is non-empty only right after a mint or roll.
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
		})
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

func (w *webApp) mintKey(rw http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		v := w.connectView(r, "")
		v.Error = "give the key a name — events and rolls are tracked by it"
		w.render(rw, "connect", v)
		return
	}
	a := &adminEnv{e: w.e, reg: w.reg}
	row, plaintext, err := a.mint(r, name)
	if err != nil {
		v := w.connectView(r, "")
		v.Error = err.Error()
		w.render(rw, "connect", v)
		return
	}
	v := w.connectView(r, plaintext)
	v.Notice = fmt.Sprintf("Key %q minted (%s). Copy it now — it is never shown again.", name, row.Prefix)
	w.render(rw, "connect", v)
}

func (w *webApp) revokeKey(rw http.ResponseWriter, r *http.Request) {
	if err := w.e.st.RevokeAgentKey(r.Context(), r.PathValue("id"), nowMillis()); err != nil {
		v := w.connectView(r, "")
		v.Error = err.Error()
		w.render(rw, "connect", v)
		return
	}
	v := w.connectView(r, "")
	v.Notice = "Key revoked. An agent holding it is refused at its next connection."
	w.render(rw, "connect", v)
}

// rollKey mints a replacement under the same name, then revokes the old one — mint first, so
// a roll can never leave you with no working key.
func (w *webApp) rollKey(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	old, err := w.e.st.GetAgentKey(ctx, r.PathValue("id"))
	if err != nil {
		v := w.connectView(r, "")
		v.Error = "no such key"
		w.render(rw, "connect", v)
		return
	}
	a := &adminEnv{e: w.e, reg: w.reg}
	row, plaintext, err := a.mint(r, old.Name)
	if err != nil {
		v := w.connectView(r, "")
		v.Error = err.Error()
		w.render(rw, "connect", v)
		return
	}
	if err := w.e.st.RevokeAgentKey(ctx, old.ID, nowMillis()); err != nil {
		v := w.connectView(r, plaintext)
		v.Error = fmt.Sprintf("new key minted (%s) but revoking the old one failed: %v", row.Prefix, err)
		w.render(rw, "connect", v)
		return
	}
	v := w.connectView(r, plaintext)
	v.Notice = fmt.Sprintf("Rolled %q — the old key is revoked. Copy the new one now.", old.Name)
	w.render(rw, "connect", v)
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
		w.render(rw, "connect", v)
		return
	}
	if err := w.e.st.SetAgentKeyConsentChannels(r.Context(), r.PathValue("id"), channels); err != nil {
		v := w.connectView(r, "")
		v.Error = err.Error()
		w.render(rw, "connect", v)
		return
	}
	v := w.connectView(r, "")
	v.Notice = "Consent channel set to " + presetLabel(channels) + ". It applies the next time that agent connects."
	w.render(rw, "connect", v)
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
