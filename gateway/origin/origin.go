// Package origin answers one question: is this request going to the server a credential was
// configured for?
//
// A credential is attached to each outgoing request by an http.RoundTripper. The same
// RoundTripper also carries the requests http.Client makes when it follows a redirect, and it
// runs after Client has removed Authorization for a new host. A transport that attaches the
// credential to everything it carries therefore puts it back, and hands it to whatever host
// the upstream redirected to. Transports check the request against the endpoint's Origin
// first.
package origin

import (
	"net/url"
	"strings"
)

// Origin is a scheme, host and port. The zero value matches no request, so a credential bound
// to an endpoint that could not be parsed is sent nowhere.
type Origin struct {
	scheme, host, port string
}

// Of returns the origin of an endpoint URL. It returns the zero Origin unless the URL is http
// or https and names a host.
func Of(endpoint string) Origin {
	u, err := url.Parse(endpoint)
	if err != nil {
		return Origin{}
	}
	return OfURL(u)
}

// OfURL is Of for a URL that is already parsed. A nil URL has the zero Origin.
func OfURL(u *url.URL) Origin {
	if u == nil {
		return Origin{}
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if host == "" {
		return Origin{}
	}
	switch scheme {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
	default:
		return Origin{}
	}
	return Origin{scheme: scheme, host: host, port: port}
}

// Has reports whether u is on this origin: the same scheme, host and port. A subdomain, another
// port on the same host, and the same host over the other scheme are all different origins.
func (o Origin) Has(u *url.URL) bool {
	return o != Origin{} && o == OfURL(u)
}
