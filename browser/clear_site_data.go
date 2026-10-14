package browser

import (
	"strings"

	http "github.com/aarock1234/fphttp"
)

// Clear-Site-Data is considered only in an explicit credentialed browser
// context. The caller clears hint state before considering opt-ins on this
// response, and must ignore Accept-CH and Critical-CH when this returns true.
func clearSiteDataClientHints(response *http.Response, metadata *RequestContext, profile *Profile) bool {
	if response == nil || response.Request == nil || metadata == nil || !headerTrustworthy(response.Request.URL) {
		return false
	}
	if !chromiumClientHints(profile) {
		return false
	}
	engineMajor, _ := identityMajor(profile.descriptor.EngineVersion)
	if engineMajor < 120 {
		// Chrome 120's exact release source explicitly implements this type.
		// Earlier inventory rows do not establish the same clearing policy.
		return false
	}
	if engineMajor >= 150 {
		// Chrome 150 introduced this restriction in clear_site_data_utils.cc.
		// A top-level navigation establishes the destination's first-party site.
		firstParty := metadata.TopLevelOrigin
		if firstParty == nil {
			firstParty = metadata.Initiator
			if metadata.IsNavigation() {
				firstParty = response.Request.URL
			}
		}
		if firstParty != nil && headerSiteRelation(firstParty, response.Request.URL) == 2 {
			return false
		}
	}
	credentials := metadata.credentialsMode()
	if credentials == CredentialsOmit || credentials == CredentialsSameOrigin && !sameHeaderOrigin(metadata.Initiator, response.Request.URL) {
		return false
	}
	value := strings.Join(response.Header.Values("Clear-Site-Data"), ",")
	if value == "" {
		return false
	}
	for index := range len(value) {
		if value[index] > 0x7f {
			return false
		}
	}
	// Chromium splits this header on commas and compares quoted literals.
	// An unrecognized entry does not invalidate other recognized directives.
	for _, directive := range strings.Split(value, ",") {
		switch strings.TrimSpace(directive) {
		case `"clientHints"`, `"cache"`, `"cookies"`, `"*"`:
			return true
		}
	}

	return false
}
