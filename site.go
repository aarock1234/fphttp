package http

import (
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// siteRelation is how two URLs relate in the sense of Sec-Fetch-Site,
// ordered from closest to farthest so that the farthest relation of a
// redirect chain is the largest value.
type siteRelation uint8

// URL relations, closest first.
const (
	// relationSameOrigin is the same scheme, host, and port.
	relationSameOrigin siteRelation = iota

	// relationSameSite is the same scheme and registrable domain
	// (schemeful same-site), but not the same origin.
	relationSameSite

	// relationCrossSite is any other relation, including any opaque
	// origin.
	relationCrossSite
)

// secFetchSite returns the Sec-Fetch-Site value of the relation.
func (r siteRelation) secFetchSite() string {
	switch r {
	case relationSameOrigin:
		return "same-origin"
	case relationSameSite:
		return "same-site"
	default:
		return "cross-site"
	}
}

// relationBetween returns how URLs a and b relate.
func relationBetween(a, b *url.URL) siteRelation {
	switch {
	case sameOrigin(a, b):
		return relationSameOrigin
	case sameSchemefulSite(a, b):
		return relationSameSite
	default:
		return relationCrossSite
	}
}

// sameSchemefulSite reports whether a and b have the same scheme and the
// same site: the same host, or hosts with the same registrable domain
// (eTLD+1) under the public suffix list. Hosts compare in their origin form
// (see originHost). An IP address is a site of its own, so two addresses
// are the same site only when they are equal.
func sameSchemefulSite(a, b *url.URL) bool {
	if a == nil || b == nil || !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}

	hostA := originHost(a.Hostname())
	hostB := originHost(b.Hostname())

	if hostA == "" || hostB == "" {
		return false
	}

	if hostA == hostB {
		return true
	}

	siteA := registrableDomain(hostA)

	return siteA != "" && siteA == registrableDomain(hostB)
}

// registrableDomain returns the eTLD+1 of a host in origin form, or "" for
// an IP address or a host that has none, such as a bare public suffix.
func registrableDomain(host string) string {
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}

	return domain
}
