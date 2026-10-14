package http

import (
	"net/url"
	"strings"
)

// referrerPolicy is a referrer policy token, as a Referrer-Policy response
// field carries it.
type referrerPolicy string

// Referrer policies (W3C Referrer Policy).
const (
	// policyNoReferrer sends no referrer.
	policyNoReferrer referrerPolicy = "no-referrer"

	// policyNoReferrerWhenDowngrade sends the full URL except on a
	// downgrade.
	policyNoReferrerWhenDowngrade referrerPolicy = "no-referrer-when-downgrade"

	// policyOrigin sends only the origin.
	policyOrigin referrerPolicy = "origin"

	// policyOriginWhenCrossOrigin sends the full URL to the same origin and
	// only the origin elsewhere.
	policyOriginWhenCrossOrigin referrerPolicy = "origin-when-cross-origin"

	// policySameOrigin sends the full URL to the same origin and nothing
	// elsewhere.
	policySameOrigin referrerPolicy = "same-origin"

	// policyStrictOrigin sends only the origin, and nothing on a downgrade.
	policyStrictOrigin referrerPolicy = "strict-origin"

	// policyStrictOriginWhenCrossOrigin sends the full URL to the same
	// origin, only the origin elsewhere, and nothing on a downgrade. It is
	// the browsers' default.
	policyStrictOriginWhenCrossOrigin referrerPolicy = "strict-origin-when-cross-origin"

	// policyUnsafeURL always sends the full URL.
	policyUnsafeURL referrerPolicy = "unsafe-url"
)

// defaultReferrerPolicy is the policy of a page that sets none, and of a
// request whose initiator's policy is unknown.
const defaultReferrerPolicy = policyStrictOriginWhenCrossOrigin

// maxReferrerLength is the longest full URL browsers send as a referrer;
// a longer one is reduced to its origin.
const maxReferrerLength = 4096

// valid reports whether p is one of the referrer policy tokens. The empty
// policy is not.
func (p referrerPolicy) valid() bool {
	switch p {
	case policyNoReferrer,
		policyNoReferrerWhenDowngrade,
		policyOrigin,
		policyOriginWhenCrossOrigin,
		policySameOrigin,
		policyStrictOrigin,
		policyStrictOriginWhenCrossOrigin,
		policyUnsafeURL:
		return true
	default:
		return false
	}
}

// refererField adds the Referer a browser sends on the request (see
// browserReferrer). A Referer the caller set is kept. A present but empty
// Referer on the first request of the redirect chain suppresses the field
// on every hop, even where a Client set the previous URL as Referer on a
// redirect hop; the Transport has already dropped such a Client Referer (see
// headerToPrepare).
func (g *fieldGenerator) refererField() {
	if g.has("Referer") || fieldSuppressedFold(g.chain[0].Header, "Referer") {
		return
	}

	g.addMissing("Referer", browserReferrer(g.request.Initiator, g.chain))
}

// browserReferrer returns the Referer of a request started by initiator
// whose redirect chain, oldest first, is chain, or "" for none. A request
// the user started, with a nil initiator, has none.
//
// Each hop reduces the referrer of the hop before it, starting from the
// initiator's URL, under the referrer policy in effect for that hop (see
// redirectedReferrerPolicy), as Fetch does on every redirect: a referrer
// reduced to its origin never regains its path on a later hop.
func browserReferrer(initiator *url.URL, chain []*Request) string {
	if initiator == nil {
		return ""
	}

	referrer := initiator
	policy := defaultReferrerPolicy
	value := ""

	for index, hop := range chain {
		if index > 0 {
			policy = redirectedReferrerPolicy(policy, hop.Response)

			parsed, err := url.Parse(value)
			if err != nil {
				return ""
			}

			referrer = parsed
		}

		value = reducedReferrer(referrer, hop.URL, policy)
		if value == "" {
			return ""
		}
	}

	return value
}

// chainReferrerPolicy returns the referrer policy in effect for the last
// hop of a redirect chain, oldest first: the newest valid policy that a
// redirect response set, or the default policy.
func chainReferrerPolicy(chain []*Request) referrerPolicy {
	policy := defaultReferrerPolicy

	for _, hop := range chain[1:] {
		policy = redirectedReferrerPolicy(policy, hop.Response)
	}

	return policy
}

// redirectedReferrerPolicy returns the policy in effect after a redirect
// response: the last valid token of its Referrer-Policy fields, or current
// when it sets no valid policy.
func redirectedReferrerPolicy(current referrerPolicy, redirect *Response) referrerPolicy {
	policy := current

	for _, value := range redirect.Header.Values("Referrer-Policy") {
		for token := range strings.SplitSeq(value, ",") {
			candidate := referrerPolicy(strings.TrimSpace(token))
			if candidate.valid() {
				policy = candidate
			}
		}
	}

	return policy
}

// reducedReferrer returns the referrer that policy lets a request to target
// carry, or "" for none, when the request's referrer is referrer. The full
// form drops the user information and fragment and falls back to the origin
// when longer than maxReferrerLength; the origin form ends with "/". A
// referrer with an opaque origin is never sent.
func reducedReferrer(referrer, target *url.URL, policy referrerPolicy) string {
	origin := requestOrigin(referrer)
	if origin == "" || policy == policyNoReferrer {
		return ""
	}

	originOnly := origin + "/"
	full := fullReferrer(referrer, originOnly)
	crossOrigin := !sameOrigin(referrer, target)
	downgrade := potentiallyTrustworthy(referrer) && !potentiallyTrustworthy(target)

	switch policy {
	case policySameOrigin:
		if crossOrigin {
			return ""
		}

		return full

	case policyOrigin:
		return originOnly

	case policyOriginWhenCrossOrigin:
		if crossOrigin {
			return originOnly
		}

		return full

	case policyStrictOrigin:
		if downgrade {
			return ""
		}

		return originOnly

	case policyStrictOriginWhenCrossOrigin:
		return strictReferrer(full, originOnly, crossOrigin, downgrade)

	case policyNoReferrerWhenDowngrade:
		if downgrade {
			return ""
		}

		return full

	default: // policyUnsafeURL
		return full
	}
}

// strictReferrer applies strict-origin-when-cross-origin: nothing on a
// downgrade, the origin across origins, and the full URL otherwise.
func strictReferrer(full, originOnly string, crossOrigin, downgrade bool) string {
	switch {
	case downgrade:
		return ""
	case crossOrigin:
		return originOnly
	default:
		return full
	}
}

// fullReferrer returns referrer without its user information and fragment,
// or originOnly when that is longer than maxReferrerLength.
func fullReferrer(referrer *url.URL, originOnly string) string {
	stripped := *referrer
	stripped.User = nil
	stripped.Fragment = ""
	stripped.RawFragment = ""

	full := stripped.String()
	if len(full) > maxReferrerLength {
		return originOnly
	}

	return full
}
