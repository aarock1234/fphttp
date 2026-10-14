package http

import (
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// layerProfileHeader adds to the prepared request every field of the
// profile's Header that the request does not set. The request's own value
// always wins, including a present but empty one, and both headers have
// canonical keys, so presence ignores the caller's spelling.
//
// Sensitive fields (see sensitiveProfileField) are added only while the
// redirect chain stays on the host of its first request or that host's
// subdomains (see staysOnFirstHost), so a profile's credentials never
// follow a redirect to another site. The added values are copies.
//
// An Accept-Encoding taken from the profile is recorded like a generated
// one, because the response is then encoded as the profile asked, not as
// the caller asked (see decodeResponse).
//
// A request with an H2PriorityHeader sets its own Priority, so the
// profile's Priority, even an empty one that suppresses the field, never
// replaces or removes it. The field generator treats H2PriorityHeader the
// same way (see fieldGenerator.priorityField).
func layerProfileHeader(request *Request, profile Header, chain []*Request) {
	sensitiveAllowed := staysOnFirstHost(chain)

	for name, values := range profile {
		if requestSetsField(request, name) {
			continue
		}

		if sensitiveProfileField(name) && !sensitiveAllowed {
			continue
		}

		request.Header[name] = slices.Clone(values)

		if name == "Accept-Encoding" && !emptyFieldValues(values) {
			request.profileHop.acceptEncoding = true
		}
	}
}

// requestSetsField reports whether the request sets the canonical field
// name itself. An H2PriorityHeader sets Priority.
func requestSetsField(request *Request, name string) bool {
	if _, set := request.Header[name]; set {
		return true
	}

	return name == "Priority" && request.H2PriorityHeader != ""
}

// sensitiveProfileField reports whether the canonical field name carries
// credentials, which a profile's Header must not send to another site.
func sensitiveProfileField(name string) bool {
	switch name {
	case "Authorization",
		"Proxy-Authorization",
		"Www-Authenticate",
		"Proxy-Authenticate",
		"Cookie",
		"Cookie2":
		return true
	default:
		return false
	}
}

// staysOnFirstHost reports whether every hop of a redirect chain, oldest
// first, is on the host of the first request or one of its subdomains. A
// chain without redirects always does. Hosts compare in their lowercase
// ASCII form, and an IP address or a host with a zone matches only itself.
func staysOnFirstHost(chain []*Request) bool {
	if len(chain) == 1 {
		return true
	}

	first, ok := comparableHost(chain[0].URL)
	if !ok {
		return false
	}

	for _, hop := range chain[1:] {
		host, ok := comparableHost(hop.URL)
		if !ok || !sameHostOrSubdomain(host, first) {
			return false
		}
	}

	return true
}

// comparableHost returns the lowercase ASCII host of u, and false when the
// host cannot be converted to ASCII.
func comparableHost(u *url.URL) (string, bool) {
	host, err := httpguts.PunycodeHostPort(u.Hostname())
	if err != nil {
		return "", false
	}

	return strings.ToLower(host), true
}

// sameHostOrSubdomain reports whether host is parent or a subdomain of it.
// An IPv6 address or a host with a zone, which contains ':' or '%', is
// never a subdomain.
func sameHostOrSubdomain(host, parent string) bool {
	if host == parent {
		return true
	}

	if strings.ContainsAny(host, ":%") {
		return false
	}

	return strings.HasSuffix(host, "."+parent)
}
