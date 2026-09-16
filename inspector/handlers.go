package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	listTimeout = 30 * time.Second
	callTimeout = 10 * time.Minute // a consent-gated call can wait on a human
)

// exampleConfig is the paste box's placeholder: one of each transport.
const exampleConfig = `{
  "mcpServers": {
    "delegent": {
      "command": "delegent",
      "args": ["stdio"],
      "env": { "DELEGENT_AGENT_KEY": "dgk_…" }
    },
    "deepwiki": {
      "url": "https://mcp.deepwiki.com/mcp",
      "headers": { "Authorization": "Bearer …" }
    }
  }
}`

type app struct {
	m   *Manager
	tpl *template.Template
}

func newApp(m *Manager) (*app, error) {
	tpl, err := template.New("").Funcs(template.FuncMap{
		"pretty": pretty,
		"json": func(v any) string {
			b, _ := json.Marshal(v)
			return string(b)
		},
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &app{m: m, tpl: tpl}, nil
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /{$}", a.index)
	mux.HandleFunc("GET /servers", a.servers)
	mux.HandleFunc("POST /servers", a.loadServers)
	mux.HandleFunc("GET /servers/{name}", a.workspace)
	mux.HandleFunc("POST /servers/{name}/connect", a.connect)
	mux.HandleFunc("POST /servers/{name}/disconnect", a.disconnect)
	mux.HandleFunc("POST /servers/{name}/ping", a.ping)
	mux.HandleFunc("GET /servers/{name}/info", a.info)
	mux.HandleFunc("GET /servers/{name}/tools", a.tools)
	mux.HandleFunc("GET /servers/{name}/tools/{tool}", a.tool)
	mux.HandleFunc("POST /servers/{name}/tools/{tool}", a.callTool)
	mux.HandleFunc("GET /servers/{name}/resources", a.resources)
	mux.HandleFunc("POST /servers/{name}/resources/read", a.readResource)
	mux.HandleFunc("GET /servers/{name}/prompts", a.prompts)
	mux.HandleFunc("GET /servers/{name}/prompts/{prompt}", a.prompt)
	mux.HandleFunc("POST /servers/{name}/prompts/{prompt}", a.getPrompt)
	mux.HandleFunc("GET /servers/{name}/transcript", a.transcript)
	mux.HandleFunc("POST /servers/{name}/transcript/clear", a.clearTranscript)
	mux.HandleFunc("GET /servers/{name}/elicitations", a.elicitations)
	mux.HandleFunc("POST /servers/{name}/elicitations/{id}", a.answerElicitation)
	return mux
}

// --- rendering ---

func (a *app) render(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := a.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// alert renders an inline notice. Status 200 on purpose: htmx skips swapping error statuses.
func (a *app) alert(w http.ResponseWriter, ok bool, text string) {
	a.render(w, "alert", map[string]any{"OK": ok, "Text": text})
}

type SidebarData struct {
	Servers    []*Server
	ConfigText string
	ConfigErr  string
	Selected   string
	Version    string
	Example    string
}

type pageData struct {
	SidebarData
	S *Server
}

func (a *app) sidebar(r *http.Request) SidebarData {
	return SidebarData{Servers: a.m.Servers(), ConfigText: a.m.ConfigText(), Selected: selectedFrom(r), Version: version, Example: exampleConfig}
}

// selectedFrom is the server highlighted in the list: ?s= on a full page load, or the same
// query on the page htmx is running in (it sends HX-Current-URL with every request).
func selectedFrom(r *http.Request) string {
	if s := r.URL.Query().Get("s"); s != "" {
		return s
	}
	if cur := r.Header.Get("HX-Current-URL"); cur != "" {
		if u, err := url.Parse(cur); err == nil {
			return u.Query().Get("s")
		}
	}
	return ""
}

func (a *app) server(w http.ResponseWriter, r *http.Request) (*Server, bool) {
	s, ok := a.m.Get(r.PathValue("name"))
	if !ok {
		http.Error(w, "no such server", http.StatusNotFound)
	}
	return s, ok
}

func (a *app) session(w http.ResponseWriter, r *http.Request) (*Server, *mcp.ClientSession, bool) {
	s, ok := a.server(w, r)
	if !ok {
		return nil, nil, false
	}
	sess := s.Session()
	if sess == nil {
		a.alert(w, false, "Not connected.")
		return s, nil, false
	}
	return s, sess, true
}

// --- page + servers ---

func (a *app) index(w http.ResponseWriter, r *http.Request) {
	d := pageData{SidebarData: a.sidebar(r)}
	if d.Selected != "" {
		d.S, _ = a.m.Get(d.Selected)
	}
	a.render(w, "page", d)
}

func (a *app) servers(w http.ResponseWriter, r *http.Request) {
	a.render(w, "servers", a.sidebar(r))
}

func (a *app) loadServers(w http.ResponseWriter, r *http.Request) {
	text := r.FormValue("config")
	d := a.sidebar(r)
	if err := a.m.Load(text); err != nil {
		d.ConfigErr = err.Error()
		d.ConfigText = text // keep what was typed so it can be fixed
	} else {
		d = a.sidebar(r)
	}
	a.render(w, "servers", d)
}

// --- workspace ---

func (a *app) workspace(w http.ResponseWriter, r *http.Request) {
	s, ok := a.server(w, r)
	if !ok {
		return
	}
	a.render(w, "workspace", pageData{SidebarData: a.sidebar(r), S: s})
}

func (a *app) connect(w http.ResponseWriter, r *http.Request) {
	s, ok := a.server(w, r)
	if !ok {
		return
	}
	_ = s.Connect() // the outcome shows in the workspace: status dot, error banner
	w.Header().Set("HX-Trigger", "servers")
	a.render(w, "workspace", pageData{SidebarData: a.sidebar(r), S: s})
}

func (a *app) disconnect(w http.ResponseWriter, r *http.Request) {
	s, ok := a.server(w, r)
	if !ok {
		return
	}
	s.Disconnect()
	w.Header().Set("HX-Trigger", "servers")
	a.render(w, "workspace", pageData{SidebarData: a.sidebar(r), S: s})
}

func (a *app) ping(w http.ResponseWriter, r *http.Request) {
	_, sess, ok := a.session(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	start := time.Now()
	err := sess.Ping(ctx, nil)
	w.Header().Set("HX-Trigger", "transcript")
	if err != nil {
		a.alert(w, false, "Ping failed: "+err.Error())
		return
	}
	a.alert(w, true, "Pong in "+fmtDur(time.Since(start)))
}

func (a *app) info(w http.ResponseWriter, r *http.Request) {
	s, ok := a.server(w, r)
	if !ok {
		return
	}
	a.render(w, "info", pageData{S: s})
}

// --- tools ---

type toolsData struct {
	S     *Server
	Tools []*mcp.Tool
	Err   string
}

func (a *app) listTools(r *http.Request, sess *mcp.ClientSession) ([]*mcp.Tool, error) {
	ctx, cancel := context.WithTimeout(r.Context(), listTimeout)
	defer cancel()
	res, err := sess.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	return res.Tools, nil
}

func (a *app) tools(w http.ResponseWriter, r *http.Request) {
	s, sess, ok := a.session(w, r)
	if !ok {
		return
	}
	d := toolsData{S: s}
	var err error
	if d.Tools, err = a.listTools(r, sess); err != nil {
		d.Err = err.Error()
	}
	w.Header().Set("HX-Trigger", "transcript")
	a.render(w, "tools", d)
}

func (a *app) findTool(r *http.Request, sess *mcp.ClientSession) (*mcp.Tool, error) {
	tools, err := a.listTools(r, sess)
	if err != nil {
		return nil, err
	}
	name := r.PathValue("tool")
	for _, t := range tools {
		if t.Name == name {
			return t, nil
		}
	}
	return nil, fmt.Errorf("the server no longer lists a tool named %q", name)
}

type toolData struct {
	S         *Server
	Tool      *mcp.Tool
	Fields    []Field
	HasFields bool
	Skeleton  string
}

func (a *app) tool(w http.ResponseWriter, r *http.Request) {
	s, sess, ok := a.session(w, r)
	if !ok {
		return
	}
	t, err := a.findTool(r, sess)
	if err != nil {
		a.alert(w, false, err.Error())
		return
	}
	d := toolData{S: s, Tool: t}
	d.Fields, d.HasFields = SchemaFields(t.InputSchema)
	d.Skeleton = Skeleton(d.Fields)
	a.render(w, "tool", d)
}

type resultData struct {
	Result     *mcp.CallToolResult
	Views      []contentView
	Structured string
	Raw        string
	Took       string
	Err        string
}

func (a *app) callTool(w http.ResponseWriter, r *http.Request) {
	_, sess, ok := a.session(w, r)
	if !ok {
		return
	}
	t, err := a.findTool(r, sess)
	if err != nil {
		a.alert(w, false, err.Error())
		return
	}
	if err := r.ParseForm(); err != nil {
		a.alert(w, false, "bad form: "+err.Error())
		return
	}
	fields, _ := SchemaFields(t.InputSchema)
	args, err := ArgsFromForm(fields, r.Form)
	if err != nil {
		a.alert(w, false, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	start := time.Now()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: t.Name, Arguments: args})
	d := resultData{Result: res, Took: fmtDur(time.Since(start))}
	if err != nil {
		d.Err = err.Error()
	} else {
		d.Views = contentViews(res.Content)
		d.Structured = pretty(res.StructuredContent)
		d.Raw = pretty(res)
	}
	w.Header().Set("HX-Trigger", "transcript")
	a.render(w, "result", d)
}

// --- resources ---

type resourcesData struct {
	S         *Server
	Resources []*mcp.Resource
	Templates []*mcp.ResourceTemplate
	Err       string
}

func (a *app) resources(w http.ResponseWriter, r *http.Request) {
	s, sess, ok := a.session(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), listTimeout)
	defer cancel()
	d := resourcesData{S: s}
	if res, err := sess.ListResources(ctx, nil); err != nil {
		d.Err = err.Error()
	} else {
		d.Resources = res.Resources
	}
	// Templates are optional; a server that only lacks them should not read as broken.
	if res, err := sess.ListResourceTemplates(ctx, nil); err == nil {
		d.Templates = res.ResourceTemplates
	}
	w.Header().Set("HX-Trigger", "transcript")
	a.render(w, "resources", d)
}

func (a *app) readResource(w http.ResponseWriter, r *http.Request) {
	_, sess, ok := a.session(w, r)
	if !ok {
		return
	}
	uri := strings.TrimSpace(r.FormValue("uri"))
	if uri == "" {
		a.alert(w, false, "Enter a URI to read.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), listTimeout)
	defer cancel()
	start := time.Now()
	res, err := sess.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
	d := map[string]any{"Took": fmtDur(time.Since(start))}
	if err != nil {
		d["Err"] = err.Error()
	} else {
		d["Views"] = resourceViews(res.Contents)
	}
	w.Header().Set("HX-Trigger", "transcript")
	a.render(w, "resource", d)
}

// --- prompts ---

type promptsData struct {
	S       *Server
	Prompts []*mcp.Prompt
	Err     string
}

func (a *app) listPrompts(r *http.Request, sess *mcp.ClientSession) ([]*mcp.Prompt, error) {
	ctx, cancel := context.WithTimeout(r.Context(), listTimeout)
	defer cancel()
	res, err := sess.ListPrompts(ctx, nil)
	if err != nil {
		return nil, err
	}
	return res.Prompts, nil
}

func (a *app) prompts(w http.ResponseWriter, r *http.Request) {
	s, sess, ok := a.session(w, r)
	if !ok {
		return
	}
	d := promptsData{S: s}
	var err error
	if d.Prompts, err = a.listPrompts(r, sess); err != nil {
		d.Err = err.Error()
	}
	w.Header().Set("HX-Trigger", "transcript")
	a.render(w, "prompts", d)
}

func (a *app) findPrompt(r *http.Request, sess *mcp.ClientSession) (*mcp.Prompt, error) {
	prompts, err := a.listPrompts(r, sess)
	if err != nil {
		return nil, err
	}
	name := r.PathValue("prompt")
	for _, p := range prompts {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, fmt.Errorf("the server no longer lists a prompt named %q", name)
}

func (a *app) prompt(w http.ResponseWriter, r *http.Request) {
	s, sess, ok := a.session(w, r)
	if !ok {
		return
	}
	p, err := a.findPrompt(r, sess)
	if err != nil {
		a.alert(w, false, err.Error())
		return
	}
	a.render(w, "prompt", map[string]any{"S": s, "Prompt": p})
}

type promptMessageView struct {
	Role  string
	Views []contentView
}

func (a *app) getPrompt(w http.ResponseWriter, r *http.Request) {
	_, sess, ok := a.session(w, r)
	if !ok {
		return
	}
	p, err := a.findPrompt(r, sess)
	if err != nil {
		a.alert(w, false, err.Error())
		return
	}
	args := map[string]string{}
	for _, arg := range p.Arguments {
		if v := r.FormValue("a." + arg.Name); v != "" {
			args[arg.Name] = v
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), listTimeout)
	defer cancel()
	start := time.Now()
	res, err := sess.GetPrompt(ctx, &mcp.GetPromptParams{Name: p.Name, Arguments: args})
	d := map[string]any{"Took": fmtDur(time.Since(start))}
	if err != nil {
		d["Err"] = err.Error()
	} else {
		var msgs []promptMessageView
		for _, m := range res.Messages {
			msgs = append(msgs, promptMessageView{Role: string(m.Role), Views: contentViews([]mcp.Content{m.Content})})
		}
		d["Messages"] = msgs
		d["Description"] = res.Description
	}
	w.Header().Set("HX-Trigger", "transcript")
	a.render(w, "promptResult", d)
}

// --- transcript ---

func (a *app) transcript(w http.ResponseWriter, r *http.Request) {
	s, ok := a.server(w, r)
	if !ok {
		return
	}
	after, _ := strconv.Atoi(r.FormValue("after"))
	entries := s.Transcript.Since(after)
	if len(entries) == 0 {
		w.WriteHeader(http.StatusNoContent) // htmx leaves the DOM alone
		return
	}
	a.render(w, "transcriptRows", map[string]any{"Entries": entries, "LastSeq": entries[0].Seq})
}

func (a *app) clearTranscript(w http.ResponseWriter, r *http.Request) {
	s, ok := a.server(w, r)
	if !ok {
		return
	}
	s.Transcript.Clear()
	a.render(w, "transcriptRows", map[string]any{"LastSeq": s.Transcript.LastSeq()})
}

// --- elicitations ---

type elicitData struct {
	S       *Server
	Current *Elicitation
	More    int
	Known   string
}

func (a *app) elicitView(s *Server) elicitData {
	pend := s.Pending()
	ids := make([]string, len(pend))
	for i, e := range pend {
		ids[i] = e.ID
	}
	d := elicitData{S: s, Known: strings.Join(ids, ",")}
	if len(pend) > 0 {
		d.Current, d.More = pend[0], len(pend)-1
	}
	return d
}

func (a *app) elicitations(w http.ResponseWriter, r *http.Request) {
	s, ok := a.server(w, r)
	if !ok {
		return
	}
	d := a.elicitView(s)
	// Unchanged set → 204, so a form someone is typing into is never re-rendered under them.
	if d.Known == r.FormValue("known") {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	a.render(w, "elicitations", d)
}

func (a *app) answerElicitation(w http.ResponseWriter, r *http.Request) {
	s, ok := a.server(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		a.alert(w, false, "bad form: "+err.Error())
		return
	}
	id := r.PathValue("id")
	res := &mcp.ElicitResult{Action: r.FormValue("action")}
	if res.Action == "accept" {
		for _, e := range s.Pending() {
			if e.ID == id {
				content, err := ArgsFromForm(e.Fields, r.Form)
				if err != nil {
					a.alert(w, false, err.Error())
					return
				}
				res.Content = content
			}
		}
	}
	if !s.Answer(id, res) {
		log.Printf("elicitation %s: already gone", id)
	}
	w.Header().Set("HX-Trigger", "transcript")
	a.render(w, "elicitations", a.elicitView(s))
}

// --- content rendering ---

// contentView is one tool-result / resource / prompt content item, flattened for the template.
type contentView struct {
	Kind    string // text · image · audio · link · resource · other
	Text    string
	MIME    string
	DataURI template.URL
	URI     string
	Name    string
	Raw     string
}

func dataURI(mime string, data []byte) template.URL {
	if mime == "" {
		mime = "application/octet-stream"
	}
	return template.URL("data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data))
}

func contentViews(cs []mcp.Content) []contentView {
	out := make([]contentView, 0, len(cs))
	for _, c := range cs {
		switch v := c.(type) {
		case *mcp.TextContent:
			out = append(out, contentView{Kind: "text", Text: v.Text})
		case *mcp.ImageContent:
			out = append(out, contentView{Kind: "image", MIME: v.MIMEType, DataURI: dataURI(v.MIMEType, v.Data)})
		case *mcp.AudioContent:
			out = append(out, contentView{Kind: "audio", MIME: v.MIMEType, DataURI: dataURI(v.MIMEType, v.Data)})
		case *mcp.ResourceLink:
			out = append(out, contentView{Kind: "link", URI: v.URI, Name: v.Name, MIME: v.MIMEType})
		case *mcp.EmbeddedResource:
			if v.Resource != nil {
				out = append(out, resourceViews([]*mcp.ResourceContents{v.Resource})...)
			}
		default:
			out = append(out, contentView{Kind: "other", Raw: pretty(c)})
		}
	}
	return out
}

func resourceViews(rs []*mcp.ResourceContents) []contentView {
	out := make([]contentView, 0, len(rs))
	for _, r := range rs {
		v := contentView{Kind: "resource", URI: r.URI, MIME: r.MIMEType, Text: r.Text}
		if r.Text == "" && len(r.Blob) > 0 {
			v.DataURI = dataURI(r.MIMEType, r.Blob)
		}
		out = append(out, v)
	}
	return out
}

func fmtDur(d time.Duration) string {
	if d >= time.Second {
		return fmt.Sprintf("%.1f s", d.Seconds())
	}
	return fmt.Sprintf("%d ms", d.Milliseconds())
}
