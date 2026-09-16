package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ServerSpec is one entry of an mcpServers map — the shape Claude Desktop, Claude Code and
// Cursor read, so a block can be pasted straight out of those config files. "type" is
// optional: a url means streamable HTTP, a command means stdio, "sse" selects the legacy
// SSE transport.
type ServerSpec struct {
	Name    string            `json:"-"`
	Type    string            `json:"type,omitempty"`
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Cwd     string            `json:"cwd,omitempty"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	// StandaloneSSE opts an HTTP server into the standalone SSE stream — the extra long-lived
	// GET the client opens so the server can push messages outside a request (a tool-list-changed
	// notification, say). Off by default because some servers are slow to answer that GET, which
	// stalls connect by many seconds; request/response and elicitation during a tool call work
	// either way. Non-standard field, ignored by other MCP clients.
	StandaloneSSE bool `json:"standaloneSSE,omitempty"`
}

const (
	KindStdio = "stdio"
	KindHTTP  = "http"
	KindSSE   = "sse"
)

// Kind resolves the transport: an explicit type wins, otherwise url → http, command → stdio.
func (s *ServerSpec) Kind() string {
	switch strings.ToLower(strings.TrimSpace(s.Type)) {
	case "stdio":
		return KindStdio
	case "http", "streamable-http", "streamablehttp", "streamable_http":
		return KindHTTP
	case "sse":
		return KindSSE
	}
	if s.URL != "" {
		return KindHTTP
	}
	return KindStdio
}

func (s *ServerSpec) Validate() error {
	switch s.Kind() {
	case KindStdio:
		if s.Command == "" {
			return fmt.Errorf("%q: a stdio server needs a command", s.Name)
		}
	default:
		if s.URL == "" {
			return fmt.Errorf("%q: an %s server needs a url", s.Name, s.Kind())
		}
	}
	return nil
}

// Summary is the one-line description under the server's name in the list.
func (s *ServerSpec) Summary() string {
	if s.Kind() == KindStdio {
		return strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
	}
	return s.URL
}

type configFile struct {
	MCPServers map[string]*ServerSpec `json:"mcpServers"`
}

// ParseConfig accepts {"mcpServers": {...}} or a bare {name: spec, ...} map and returns the
// specs sorted by name. Every spec must be usable; the first problem is the error.
func ParseConfig(data []byte) ([]*ServerSpec, error) {
	var cf configFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if cf.MCPServers == nil {
		var bare map[string]*ServerSpec
		if err := json.Unmarshal(data, &bare); err != nil || len(bare) == 0 {
			return nil, errors.New(`expected {"mcpServers": {"name": {...}}}`)
		}
		cf.MCPServers = bare
	}
	specs := make([]*ServerSpec, 0, len(cf.MCPServers))
	for name, s := range cf.MCPServers {
		if s == nil {
			return nil, fmt.Errorf("%q: empty server entry", name)
		}
		s.Name = name
		if err := s.Validate(); err != nil {
			return nil, err
		}
		specs = append(specs, s)
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].Name < specs[j].Name })
	return specs, nil
}

// MarshalConfig renders specs back as {"mcpServers": {...}} — what the paste box shows on
// the next visit.
func MarshalConfig(specs []*ServerSpec) []byte {
	cf := configFile{MCPServers: map[string]*ServerSpec{}}
	for _, s := range specs {
		cf.MCPServers[s.Name] = s
	}
	b, _ := json.MarshalIndent(cf, "", "  ")
	return append(b, '\n')
}

// LoadConfigFile reads a saved config; a missing file is an empty list, not an error.
func LoadConfigFile(path string) ([]*ServerSpec, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

func SaveConfigFile(path string, specs []*ServerSpec) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, MarshalConfig(specs), 0o600)
}

// DefaultConfigPath is <user config dir>/mcp-inspector/servers.json.
func DefaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "mcp-inspector.json"
	}
	return filepath.Join(dir, "mcp-inspector", "servers.json")
}
