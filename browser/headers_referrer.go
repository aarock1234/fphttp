package browser

import (
	"net/url"
	"strings"

	http "github.com/aarock1234/fphttp/v2"
)

// Redirects carry forward the previously reduced referrer and adopt the last
// recognized response policy. A later hop cannot restore a removed URL path.
func contextRequestReferrer(req *http.Request, metadata *RequestContext) (string, ReferrerPolicy) {
	referrer := metadata.Referrer
	policy := metadata.ReferrerPolicy
	if previous := req.Response; previous != nil && previous.Request != nil {
		referrer = nil
		present, values := requestHeader(previous.Request.Header, "Referer")
		if present && !headerSuppressed(values) {
			parsed, err := url.Parse(strings.TrimSpace(values[0]))
			if err == nil && parsed.Opaque == "" && headerOrigin(parsed) != "" {
				referrer = parsed
			}
		}
	}
	for response := req.Response; response != nil && response.Request != nil; response = response.Request.Response {
		if redirectedPolicy := responseReferrerPolicy(response.Header); redirectedPolicy != ReferrerDefault {
			policy = redirectedPolicy
			break
		}
	}

	return contextReferrer(referrer, req.URL, policy), policy
}

func responseReferrerPolicy(headers http.Header) ReferrerPolicy {
	var policy ReferrerPolicy
	for _, value := range headers.Values("Referrer-Policy") {
		for _, token := range strings.Split(value, ",") {
			candidate := ReferrerPolicy(strings.TrimSpace(token))
			if candidate != ReferrerDefault && validReferrerPolicy(candidate) {
				policy = candidate
			}
		}
	}

	return policy
}

func contextReferrer(referrer, destination *url.URL, policy ReferrerPolicy) string {
	if referrer == nil || destination == nil || policy == ReferrerNoReferrer {
		return ""
	}
	full := *referrer
	full.User = nil
	full.Fragment = ""
	full.RawFragment = ""
	value := full.String()
	origin := headerOrigin(referrer) + "/"
	if len(value) > 4096 {
		value = origin
	}
	sameOrigin := sameHeaderOrigin(referrer, destination)
	downgrade := headerTrustworthy(referrer) && !headerTrustworthy(destination)
	switch policy {
	case ReferrerSameOrigin:
		if !sameOrigin {
			return ""
		}
	case ReferrerOrigin:
		return origin
	case ReferrerOriginWhenCrossOrigin:
		if !sameOrigin {
			return origin
		}
	case ReferrerStrictOrigin:
		if downgrade {
			return ""
		}

		return origin
	case ReferrerDefault, ReferrerStrictOriginWhenCrossOrigin:
		if downgrade {
			return ""
		}
		if !sameOrigin {
			return origin
		}
	case ReferrerNoReferrerWhenDowngrade:
		if downgrade {
			return ""
		}
	}

	return value
}
