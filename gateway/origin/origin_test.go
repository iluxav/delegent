package origin

import (
	"net/url"
	"testing"
)

func TestHas(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		request  string
		want     bool
	}{
		{"same url", "https://mcp.vendor.com/mcp", "https://mcp.vendor.com/mcp", true},
		{"another path on the same origin", "https://mcp.vendor.com/mcp", "https://mcp.vendor.com/v2/mcp?x=1", true},
		{"default https port written out", "https://mcp.vendor.com/mcp", "https://mcp.vendor.com:443/mcp", true},
		{"default http port written out", "http://localhost/mcp", "http://localhost:80/mcp", true},
		{"host in another case", "https://MCP.Vendor.com/mcp", "https://mcp.vendor.com/mcp", true},
		{"explicit port, same", "http://127.0.0.1:8090/mcp", "http://127.0.0.1:8090/other", true},
		{"ipv6, same", "http://[::1]:8090/mcp", "http://[::1]:8090/mcp", true},
		{"user info is not part of the origin", "https://mcp.vendor.com/mcp", "https://someone@mcp.vendor.com/mcp", true},

		{"another host", "https://mcp.vendor.com/mcp", "https://other-host.example/mcp", false},
		{"a subdomain", "https://vendor.com/mcp", "https://evil.vendor.com/mcp", false},
		{"the parent domain", "https://mcp.vendor.com/mcp", "https://vendor.com/mcp", false},
		{"a host that only starts the same", "https://vendor.com/mcp", "https://vendor.com.evil.example/mcp", false},
		{"another port on the same host", "http://127.0.0.1:8090/mcp", "http://127.0.0.1:8091/mcp", false},
		{"https down to http", "https://mcp.vendor.com/mcp", "http://mcp.vendor.com/mcp", false},
		{"http up to https", "http://mcp.vendor.com/mcp", "https://mcp.vendor.com/mcp", false},
		{"http on the https port", "https://mcp.vendor.com/mcp", "http://mcp.vendor.com:443/mcp", false},
		{"host with a trailing dot", "https://mcp.vendor.com/mcp", "https://mcp.vendor.com./mcp", false},
	}
	for _, c := range cases {
		u, err := url.Parse(c.request)
		if err != nil {
			t.Fatalf("%s: parse %q: %v", c.name, c.request, err)
		}
		if got := Of(c.endpoint).Has(u); got != c.want {
			t.Errorf("%s: Of(%q).Has(%q) = %v, want %v", c.name, c.endpoint, c.request, got, c.want)
		}
	}
}

// An endpoint that cannot be an HTTP origin matches nothing, itself included: a credential
// bound to it is never sent.
func TestZeroOriginMatchesNothing(t *testing.T) {
	for _, endpoint := range []string{"", "not a url", "://nohost", "/just/a/path", "ftp://vendor.com/mcp", "https:///mcp", "http://bad host/"} {
		o := Of(endpoint)
		if o != (Origin{}) {
			t.Errorf("Of(%q) = %+v, want the zero Origin", endpoint, o)
		}
		if u, err := url.Parse(endpoint); err == nil && o.Has(u) {
			t.Errorf("Of(%q) matched its own URL", endpoint)
		}
	}
	if (Origin{}).Has(nil) {
		t.Error("the zero Origin matched a nil URL")
	}
	u, _ := url.Parse("https://mcp.vendor.com/mcp")
	if (Origin{}).Has(u) {
		t.Error("the zero Origin matched a real URL")
	}
}
