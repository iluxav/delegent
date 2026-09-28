package main

import (
	"io/fs"
	"net/http"
	"net/url"
)

// catalogServer is one well-known remote MCP server the add page offers as a one-click tile.
// Every entry speaks Streamable HTTP. Most do OAuth with dynamic client registration, so the
// tile only has to post a name and an endpoint — createTarget's no-token path does the rest.
// A server with no registration endpoint (GitHub) can still take a token the operator mints;
// its tile opens the add form prefilled instead, with a link to where that token is made (see
// tokenServers). One that refuses both (Figma returns 403) is left out. Logos are Simple Icons (CC0), in
// web/static/brands/<ID>.svg, and render as a mask so they take the theme's ink colour. A
// server Simple Icons does not carry (Monday, Firecrawl) shows the generic server glyph.
type catalogServer struct {
	ID, Name, Blurb, Endpoint string
	Category                  string // one of catalogCategories
}

// catalogCategories is the order the add page groups the catalog in. Every entry's Category
// must be one of these (TestCatalogCategories holds that).
var catalogCategories = []string{
	"Developer",
	"Deploy & hosting",
	"Work & planning",
	"Design & sites",
	"Data",
	"Payments",
	"Support",
	"Web & automation",
}

var popularServers = []catalogServer{
	{"notion", "Notion", "Pages, databases, and search", "https://mcp.notion.com/mcp", "Work & planning"},
	{"linear", "Linear", "Issues, projects, and cycles", "https://mcp.linear.app/mcp", "Work & planning"},
	{"atlassian", "Atlassian", "Jira and Confluence", "https://mcp.atlassian.com/v1/mcp", "Work & planning"},
	{"sentry", "Sentry", "Errors, traces, and releases", "https://mcp.sentry.dev/mcp", "Developer"},
	{"stripe", "Stripe", "Payments, customers, and billing", "https://mcp.stripe.com", "Payments"},
	{"supabase", "Supabase", "Postgres, auth, and edge functions", "https://mcp.supabase.com/mcp", "Data"},
	{"zapier", "Zapier", "Actions across thousands of apps", "https://mcp.zapier.com/api/mcp/mcp", "Web & automation"},
	{"canva", "Canva", "Designs, assets, and exports", "https://mcp.canva.com/mcp", "Design & sites"},
	{"cloudflare", "Cloudflare", "Workers, KV, R2, and D1", "https://bindings.mcp.cloudflare.com/mcp", "Deploy & hosting"},
	{"paypal", "PayPal", "Invoices, orders, and payments", "https://mcp.paypal.com/mcp", "Payments"},
	{"vercel", "Vercel", "Projects, deployments, and logs", "https://mcp.vercel.com", "Deploy & hosting"},
	{"github", "GitHub", "Repositories, issues, and pull requests", "https://api.githubcopilot.com/mcp/", "Developer"},
	{"gitlab", "GitLab", "Projects, issues, and merge requests", "https://gitlab.com/api/v4/mcp", "Developer"},
	{"netlify", "Netlify", "Sites, deploys, and forms", "https://netlify-mcp.netlify.app/mcp", "Deploy & hosting"},
	{"webflow", "Webflow", "Sites, pages, and CMS content", "https://mcp.webflow.com/mcp", "Design & sites"},
	{"intercom", "Intercom", "Conversations, contacts, and tickets", "https://mcp.intercom.com/mcp", "Support"},
	{"airtable", "Airtable", "Bases, tables, and records", "https://mcp.airtable.com/mcp", "Work & planning"},
	{"monday", "Monday", "Boards, items, and updates", "https://mcp.monday.com/mcp", "Work & planning"},
	{"firecrawl", "Firecrawl", "Web search, scraping, and crawls", "https://mcp.firecrawl.dev/v2/mcp", "Web & automation"},
}

// tokenServers are the catalog entries that cannot do OAuth sign-in on their own, keyed by ID,
// with the page where the operator mints the token to paste instead.
var tokenServers = map[string]string{
	"github":    "https://github.com/settings/personal-access-tokens/new",
	"firecrawl": "https://www.firecrawl.dev/app/api-keys",
}

// hasLogo reports whether a brand logo ships for this catalog ID.
func hasLogo(id string) bool {
	_, err := fs.Stat(webStatic, "web/static/brands/"+id+".svg")
	return err == nil
}

// Logo is the tile's logo: the brand's own, or the generic server glyph when none ships.
func (s catalogServer) Logo() string {
	if hasLogo(s.ID) {
		return "/static/brands/" + s.ID + ".svg"
	}
	return "/static/server.svg"
}

// TokenURL is where this server's token is made, or "" for a server that signs in with OAuth.
func (s catalogServer) TokenURL() string { return tokenServers[s.ID] }

// catalogByID finds a catalog entry by its ID.
func catalogByID(id string) (catalogServer, bool) {
	for _, s := range popularServers {
		if s.ID == id {
			return s, true
		}
	}
	return catalogServer{}, false
}

// Host is the endpoint's host, shown on the tile so the operator sees where it connects.
func (s catalogServer) Host() string {
	if u, err := url.Parse(s.Endpoint); err == nil && u.Host != "" {
		return u.Host
	}
	return s.Endpoint
}

// catalogTile is a catalog entry as the add page shows it: AddedAs names the target already
// connected to that endpoint, so the tile links there instead of offering a second sign-in.
type catalogTile struct {
	catalogServer
	AddedAs string
}

// catalogGroup is one category of the add page's catalog, in catalogCategories order.
type catalogGroup struct {
	Name  string
	Tiles []catalogTile
}

// catalog is the add page's catalog: every server, grouped by category, with a total.
type catalog struct {
	Groups []catalogGroup
	Total  int
}

// Match known endpoints, rather than an operator-supplied display name.
func catalogBrand(endpoint string) string {
	for _, server := range popularServers {
		if server.Endpoint == endpoint && hasLogo(server.ID) {
			return server.ID
		}
	}
	return ""
}

func (w *webApp) catalogTiles(r *http.Request) catalog {
	added := map[string]string{}
	if ts, err := w.e.st.ListTargets(r.Context()); err == nil {
		for _, t := range ts {
			added[t.Endpoint] = t.ID
		}
	}
	byCat := map[string][]catalogTile{}
	for _, s := range popularServers {
		byCat[s.Category] = append(byCat[s.Category], catalogTile{catalogServer: s, AddedAs: added[s.Endpoint]})
	}
	c := catalog{Total: len(popularServers)}
	for _, name := range catalogCategories {
		if tiles := byCat[name]; len(tiles) > 0 {
			c.Groups = append(c.Groups, catalogGroup{Name: name, Tiles: tiles})
		}
	}
	return c
}
