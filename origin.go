package http

import (
	"net/netip"
	"net/url"
	"strings"
)

// requestOrigin returns the ASCII serialization of the origin of u, such as
// "https://example.com" or "http://127.0.0.1:8080", or "" when u is nil or
// has an opaque origin: a scheme other than http and https, or no usable
// host.
//
// The scheme and host are lowercased, a domain takes its IDNA ASCII form,
// an IP address its canonical text form, and the scheme's default port is
// dropped, so URLs that browsers treat as one origin serialize alike.
func requestOrigin(u *url.URL) string {
	if u == nil {
		return ""
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}

	host := originHost(u.Hostname())
	if host == "" {
		return ""
	}

	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}

	port := u.Port()
	if port == "" || port == schemePort(scheme) {
		return scheme + "://" + host
	}

	return scheme + "://" + host + ":" + port
}

// originHost returns hostname in the form origins compare it: an IP address
// in canonical text form, or a lowercased domain in IDNA ASCII form. It
// returns "" when hostname is empty or not a valid domain.
func originHost(hostname string) string {
	host := strings.ToLower(hostname)
	if host == "" {
		return ""
	}

	if address, err := netip.ParseAddr(host); err == nil {
		return address.String()
	}

	ascii, err := idnaASCII(host)
	if err != nil {
		return ""
	}

	return ascii
}

// sameOrigin reports whether a and b have the same origin. An opaque origin
// is never the same as any other, including itself.
func sameOrigin(a, b *url.URL) bool {
	origin := requestOrigin(a)

	return origin != "" && origin == requestOrigin(b)
}
