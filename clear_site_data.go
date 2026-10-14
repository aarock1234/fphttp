package http

import (
	"strings"

	"github.com/aarock1234/fphttp/v2/internal/ascii"
	"github.com/aarock1234/fphttp/v2/internal/catalog"
)

// clearsClientHints reports whether resp, the response to the hop that
// sent sent, makes the release forget the client hints of the hop URL's
// origin through Clear-Site-Data. The caller has checked that the URL is
// potentially trustworthy. Clear-Site-Data clears only client hints here;
// a Client's Jar keeps its cookies.
//
// The field must list a directive that clears client hints, the release
// must apply Clear-Site-Data to client hints (see
// catalog.Entry.ClearSiteData), and the request's credentials mode must
// allow credentials for the URL, as for cookies (see
// Request.carriesCredentials).
func clearsClientHints(resp *Response, sent *Request, entry *catalog.Entry) bool {
	if !clearSiteDataClearsHints(resp.Header.Values("Clear-Site-Data")) {
		return false
	}

	switch entry.ClearSiteData() {
	case catalog.ClearSiteDataIgnored:
		return false

	case catalog.ClearSiteDataFirstParty:
		if crossSiteToTopLevel(sent) {
			return false
		}
	}

	return sent.carriesCredentials()
}

// crossSiteToTopLevel reports whether request's URL is cross-site to the
// top-level page it was loaded for. A top-level page load is that page.
// For any other request, the Initiator stands for the top-level page,
// which fphttp does not know apart from it, and a request without an
// Initiator counts as first-party.
func crossSiteToTopLevel(request *Request) bool {
	if request.Destination.topLevel() || request.Initiator == nil {
		return false
	}

	return relationBetween(request.Initiator, request.URL) == relationCrossSite
}

// clearSiteDataClearsHints reports whether Clear-Site-Data field values
// list a directive that clears client hints: "clientHints", "cache",
// "cookies", or "*". As Chromium does, it splits the values on commas and
// compares quoted literals, skips directives it does not know, and ignores
// a field with a byte outside ASCII.
func clearSiteDataClearsHints(values []string) bool {
	value := strings.Join(values, ",")
	if !ascii.Is(value) {
		return false
	}

	for directive := range strings.SplitSeq(value, ",") {
		switch strings.TrimSpace(directive) {
		case `"clientHints"`, `"cache"`, `"cookies"`, `"*"`:
			return true
		}
	}

	return false
}
