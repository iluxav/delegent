package main

import (
	"net/http"
)

// catalogServer is one well-known remote MCP server the add page offers as a one-click tile.
// Every entry speaks Streamable HTTP and does OAuth with dynamic client registration, so a
// tile only has to post a name and an endpoint — createTarget's no-token path does the rest.
// Servers that refuse dynamic registration (Figma returns 403, GitHub has no registration
// endpoint) are left out: the tile could only fail. Logos are Simple Icons (CC0), in
// web/static/brands/<ID>.svg, and render as a mask so they take the theme's ink colour.
type catalogServer struct {
	ID, Name, Blurb, Endpoint string
}

var popularServers = []catalogServer{
	{"notion", "Notion", "Pages, databases, and search", "https://mcp.notion.com/mcp"},
	{"linear", "Linear", "Issues, projects, and cycles", "https://mcp.linear.app/mcp"},
	{"atlassian", "Atlassian", "Jira and Confluence", "https://mcp.atlassian.com/v1/mcp"},
	{"sentry", "Sentry", "Errors, traces, and releases", "https://mcp.sentry.dev/mcp"},
	{"stripe", "Stripe", "Payments, customers, and billing", "https://mcp.stripe.com"},
	{"supabase", "Supabase", "Postgres, auth, and edge functions", "https://mcp.supabase.com/mcp"},
	{"zapier", "Zapier", "Actions across thousands of apps", "https://mcp.zapier.com/api/mcp/mcp"},
	{"canva", "Canva", "Designs, assets, and exports", "https://mcp.canva.com/mcp"},
	{"cloudflare", "Cloudflare", "Workers, KV, R2, and D1", "https://bindings.mcp.cloudflare.com/mcp"},
	{"paypal", "PayPal", "Invoices, orders, and payments", "https://mcp.paypal.com/mcp"},
}

// catalogTile is a catalog entry as the add page shows it: AddedAs names the target already
// connected to that endpoint, so the tile links there instead of offering a second sign-in.
type catalogTile struct {
	catalogServer
	AddedAs string
}

// Match known endpoints, rather than an operator-supplied display name.
func catalogBrand(endpoint string) string {
	for _, server := range popularServers {
		if server.Endpoint == endpoint {
			return server.ID
		}
	}
	return ""
}

func (w *webApp) catalogTiles(r *http.Request) []catalogTile {
	added := map[string]string{}
	if ts, err := w.e.st.ListTargets(r.Context()); err == nil {
		for _, t := range ts {
			added[t.Endpoint] = t.ID
		}
	}
	tiles := make([]catalogTile, 0, len(popularServers))
	for _, s := range popularServers {
		tiles = append(tiles, catalogTile{catalogServer: s, AddedAs: added[s.Endpoint]})
	}
	return tiles
}
