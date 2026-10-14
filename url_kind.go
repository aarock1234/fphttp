package http

import (
	"net/netip"
	"net/url"
	"strings"

	"github.com/aarock1234/fphttp/v2/internal/catalog"
)

// targetKind classifies u the way browsers do when they decide what a
// request may carry: an https URL is secure, a plain-http URL whose host is
// localhost (see localhostName) is localhost, and everything else is
// insecure.
func targetKind(u *url.URL) catalog.URLKind {
	switch {
	case u.Scheme == "https":
		return catalog.URLSecure

	case u.Scheme == "http" && localhostName(u.Hostname()):
		return catalog.URLLocalhost

	default:
		return catalog.URLInsecure
	}
}

// potentiallyTrustworthy reports whether browsers treat u as a potentially
// trustworthy URL: https, or plain http to localhost. Fetch metadata and
// client hints go only to such URLs, and a referrer leaving one for a URL
// that is not trustworthy is a downgrade.
func potentiallyTrustworthy(u *url.URL) bool {
	return targetKind(u) != catalog.URLInsecure
}

// localhostName reports whether host names the local machine: localhost, a
// .localhost subdomain, or a loopback address. A trailing dot and letter
// case are ignored.
func localhostName(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}

	address, err := netip.ParseAddr(host)

	return err == nil && address.IsLoopback()
}
