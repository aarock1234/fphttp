package http

import "net/url"

// originField adds the Origin field of a request with an Initiator when
// browsers send one (see needsOrigin). The value is the initiator's origin,
// or "null" where the redirect chain or the referrer policy hides it (see
// originValue). A request the user started carries no Origin.
//
// A WebSocket handshake always carries the Origin of the page that opens
// it (see webSocketOrigin).
func (g *fieldGenerator) originField() {
	if g.webSocket() {
		g.addMissing("Origin", webSocketOrigin(g.request))

		return
	}

	if g.request.Initiator == nil || !g.needsOrigin() {
		return
	}

	g.addMissing("Origin", g.originValue())
}

// needsOrigin reports whether a browser sends Origin on the request: always
// for a method other than GET and HEAD, and for a cors-mode request that
// leaves the initiator's origin or whose redirects taint it (see
// redirectTaintsOrigin).
func (g *fieldGenerator) needsOrigin() bool {
	request := g.request
	if !getOrHead(request.Method) {
		return true
	}

	if request.Destination.mode() != modeCORS {
		return false
	}

	crossOrigin := !sameOrigin(request.Initiator, request.URL)

	return crossOrigin || redirectTaintsOrigin(request.Initiator, g.chain)
}

// getOrHead reports whether method is GET or HEAD; "" means GET.
func getOrHead(method string) bool {
	return method == "" || method == MethodGet || method == MethodHead
}

// originValue returns the Origin value of the request: "null" for an opaque
// initiator origin or a tainted redirect chain, "null" for a request that is
// not cors-mode when the referrer policy in effect hides the origin (see
// policyHidesOrigin), and the initiator's origin otherwise.
func (g *fieldGenerator) originValue() string {
	request := g.request

	origin := requestOrigin(request.Initiator)
	if origin == "" || redirectTaintsOrigin(request.Initiator, g.chain) {
		return "null"
	}

	if request.Destination.mode() == modeCORS {
		return origin
	}

	policy := chainReferrerPolicy(g.chain)
	if policyHidesOrigin(policy, request.Initiator, request.URL) {
		return "null"
	}

	return origin
}

// policyHidesOrigin reports whether a referrer policy hides the initiator's
// origin from a request to target that is not cors-mode: always for
// no-referrer, on an https to plain-http downgrade for the policies that
// strip referrers on a downgrade, and on a cross-origin request for
// same-origin.
func policyHidesOrigin(policy referrerPolicy, initiator, target *url.URL) bool {
	switch policy {
	case policyNoReferrer:
		return true

	case policyNoReferrerWhenDowngrade, policyStrictOrigin, policyStrictOriginWhenCrossOrigin:
		return initiator.Scheme == "https" && target.Scheme != "https"

	case policySameOrigin:
		return !sameOrigin(initiator, target)

	default:
		return false
	}
}

// redirectTaintsOrigin reports whether a redirect chain, oldest first,
// taints the initiator's origin, which browsers then send as "null": some
// redirect crossed origins from a URL that was not on the initiator's own
// origin.
func redirectTaintsOrigin(initiator *url.URL, chain []*Request) bool {
	for index := 1; index < len(chain); index++ {
		from := chain[index-1].URL
		to := chain[index].URL

		if !sameOrigin(from, to) && !sameOrigin(initiator, from) {
			return true
		}
	}

	return false
}
