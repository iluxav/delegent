# mcp-inspector

A single-binary web UI for poking at MCP servers. Paste an `mcpServers` block, the same
shape Claude Desktop, Claude Code and Cursor read, connect, and inspect.

```sh
make inspector                    # from the repo root → inspector/mcp-inspector
./inspector/mcp-inspector         # http://127.0.0.1:8095
```

Flags: `-addr 127.0.0.1:8095` and `-config <file>` (where the pasted config is saved; defaults
to the OS user config dir, `~/Library/Application Support/mcp-inspector/servers.json` on macOS).

## What it does

- **Servers** from a pasted config. `command` + `args` + `env` + optional `cwd` is stdio;
  `url` + optional `headers` is streamable HTTP; `"type": "sse"` picks the legacy SSE
  transport. Env and header values never render back to the page.
- **Fast HTTP connect.** HTTP servers connect without the standalone SSE stream — the extra
  long-lived GET that some servers answer slowly, stalling connect by many seconds. Add
  `"standaloneSSE": true` to a server to opt back in when you want to watch messages the
  server pushes outside a request (a tool-list-changed notification, say). Request/response
  and elicitation raised during a tool call work either way.
- **Tools**: list, a form generated from each tool's input schema (or raw JSON), call, and
  the result with text, images, audio, embedded resources and `structuredContent` rendered.
- **Resources** and **templates**: list, read any URI. **Prompts**: list, fill arguments, get.
- **Server** tab: identity, protocol version, capabilities, instructions.
- **Transcript**: every request and notification in both directions, with params, result or
  error, and round-trip time. A stdio server's stderr shows up there too.
- **Elicitations**: when a server asks the client something (a consent gateway, for
  instance), a form opens. Accept with values, decline, or cancel.

Stdio servers run as children of the inspector and stop when you disconnect or quit.

## Layout

| file | role |
|---|---|
| `config.go` | the `mcpServers` shape, transport inference, load/save |
| `manager.go` | one `Server` per entry: connect/disconnect, session, pending elicitations |
| `transcript.go` | bounded per-server log; the client middleware that fills it |
| `forms.go` | JSON schema → form fields → arguments |
| `handlers.go` | the htmx endpoints and content rendering |
| `templates/` | html/template partials |
| `static/` | `htmx.min.js`, `input.css` (Tailwind source), `app.css` (compiled, embedded) |

Styling is Tailwind v4 compiled ahead of time, so the binary has no runtime dependency on a
CDN. After adding classes to a template run `make css` from the repo root; it downloads the standalone Tailwind CLI once into `inspector/.cache/`.
