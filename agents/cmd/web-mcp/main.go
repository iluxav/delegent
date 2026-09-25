// web-mcp is a small MCP server over Streamable HTTP with two tools that reach the internet:
// search_web (DuckDuckGo's HTML results, no API key) and fetch_page (a URL's readable text).
// Register it as an MCP target in Delegent and the researcher can do real research through
// the gateway — with the same consent and receipts as every other call.
//
//	web-mcp --port 7105 --secret secret-web
//	delegent target add --id web --endpoint http://127.0.0.1:7105/mcp --credential secret-web
package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const userAgent = "Mozilla/5.0 (X11; Linux x86_64) delegent-web-mcp/0.1"

type searchArgs struct {
	Query      string `json:"query" jsonschema:"what to search for"`
	MaxResults int    `json:"max_results,omitempty" jsonschema:"how many results to return (default 6, max 10)"`
}

type fetchArgs struct {
	URL      string `json:"url" jsonschema:"the page to read (http or https)"`
	MaxChars int    `json:"max_chars,omitempty" jsonschema:"cap on the returned text (default 6000)"`
}

type searchResult struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet"`
}

var (
	resultRe  = regexp.MustCompile(`(?s)<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>`)
	snippetRe = regexp.MustCompile(`(?s)<a[^>]+class="result__snippet"[^>]*>(.*?)</a>`)
	tagRe     = regexp.MustCompile(`(?s)<[^>]+>`)
	dropRe    = regexp.MustCompile(`(?is)<(script|style|noscript|svg|head)[^>]*>.*?</\s*(script|style|noscript|svg|head)\s*>`)
	spaceRe   = regexp.MustCompile(`[ \t\r\f\v]+`)
	blankRe   = regexp.MustCompile(`\n{3,}`)
	blockRe   = regexp.MustCompile(`(?i)</?(p|div|br|li|h[1-6]|tr|section|article|header|footer|blockquote|pre)[^>]*>`)
)

var httpClient = &http.Client{Timeout: 20 * time.Second}

func get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept-Language", "en")
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: %s", u, res.Status)
	}
	return io.ReadAll(io.LimitReader(res.Body, 2<<20))
}

func search(ctx context.Context, q string, n int) ([]searchResult, error) {
	if n <= 0 {
		n = 6
	}
	if n > 10 {
		n = 10
	}
	body, err := get(ctx, "https://html.duckduckgo.com/html/?q="+url.QueryEscape(q))
	if err != nil {
		return nil, err
	}
	links := resultRe.FindAllStringSubmatch(string(body), -1)
	snips := snippetRe.FindAllStringSubmatch(string(body), -1)
	var out []searchResult
	for i, m := range links {
		href := html.UnescapeString(m[1])
		// DuckDuckGo wraps targets as //duckduckgo.com/l/?uddg=<encoded url>&rut=…
		if u, err := url.Parse(href); err == nil {
			if real := u.Query().Get("uddg"); real != "" {
				href = real
			} else if u.Scheme == "" {
				href = "https:" + href
			}
		}
		r := searchResult{Title: clean(m[2]), URL: href}
		if i < len(snips) {
			r.Snippet = clean(snips[i][1])
		}
		out = append(out, r)
		if len(out) == n {
			break
		}
	}
	return out, nil
}

// clean turns an HTML fragment into one line of text.
func clean(s string) string {
	s = html.UnescapeString(tagRe.ReplaceAllString(s, " "))
	return strings.TrimSpace(spaceRe.ReplaceAllString(strings.ReplaceAll(s, "\n", " "), " "))
}

// readable turns a page into plain text: scripts and styles dropped, block tags as line
// breaks, entities decoded, whitespace collapsed.
func readable(page string) string {
	s := dropRe.ReplaceAllString(page, " ")
	s = blockRe.ReplaceAllString(s, "\n")
	s = tagRe.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(spaceRe.ReplaceAllString(l, " ")); l != "" {
			lines = append(lines, l)
		}
	}
	return blankRe.ReplaceAllString(strings.Join(lines, "\n"), "\n\n")
}

func main() {
	port := flag.Int("port", 7105, "port to listen on")
	host := flag.String("host", "127.0.0.1", "interface to listen on")
	secret := flag.String("secret", envOr("WEB_SECRET", "secret-web"), "bearer token callers must present (env WEB_SECRET); empty disables the check")
	flag.Parse()

	s := mcp.NewServer(&mcp.Implementation{Name: "web", Version: "0.1.0"}, &mcp.ServerOptions{
		Instructions: "Two tools for the open web: search_web finds pages, fetch_page reads one. Prefer a search, then fetch the one or two results that matter.",
	})
	yes := true
	mcp.AddTool(s, &mcp.Tool{
		Name: "search_web", Description: "Search the web (DuckDuckGo) and return the top results: title, URL, snippet.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &yes},
	}, func(ctx context.Context, req *mcp.CallToolRequest, a searchArgs) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(a.Query) == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "query is required"}}}, nil, nil
		}
		rs, err := search(ctx, a.Query, a.MaxResults)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "search failed: " + err.Error()}}}, nil, nil
		}
		var b strings.Builder
		for i, r := range rs {
			fmt.Fprintf(&b, "%d. %s\n   %s\n", i+1, r.Title, r.URL)
			if r.Snippet != "" {
				fmt.Fprintf(&b, "   %s\n", r.Snippet)
			}
		}
		if b.Len() == 0 {
			b.WriteString("no results")
		}
		log.Printf("search_web %q → %d results", a.Query, len(rs))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, map[string]any{"results": rs}, nil
	})
	mcp.AddTool(s, &mcp.Tool{
		Name: "fetch_page", Description: "Fetch a web page and return its readable text (scripts, styles and markup removed).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &yes},
	}, func(ctx context.Context, req *mcp.CallToolRequest, a fetchArgs) (*mcp.CallToolResult, any, error) {
		u, err := url.Parse(strings.TrimSpace(a.URL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "url must be an http(s) address"}}}, nil, nil
		}
		body, err := get(ctx, u.String())
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "fetch failed: " + err.Error()}}}, nil, nil
		}
		text := readable(string(body))
		max := a.MaxChars
		if max <= 0 {
			max = 6000
		}
		if r := []rune(text); len(r) > max {
			text = string(r[:max]) + fmt.Sprintf("\n\n[truncated: %d of %d characters]", max, len(r))
		}
		log.Printf("fetch_page %s → %d chars", u, len(text))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
	})

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
	mux := http.NewServeMux()
	mux.Handle("/mcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *secret != "" {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(tok), []byte(*secret)) != 1 {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		handler.ServeHTTP(w, r)
	}))
	addr := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("web-mcp up at http://%s/mcp · tools search_web, fetch_page · bearer %q", addr, *secret)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
