package catalog

// ClearSiteDataRule is how a release applies a Clear-Site-Data response
// field to the client hints an origin asked for with Accept-CH.
type ClearSiteDataRule uint8

// Ways a release applies Clear-Site-Data to client hints.
const (
	// ClearSiteDataIgnored keeps client hints: the release sends none, or its
	// source does not establish that Clear-Site-Data clears them.
	ClearSiteDataIgnored ClearSiteDataRule = iota

	// ClearSiteDataClears forgets the client hints of a response's origin
	// when its Clear-Site-Data lists "clientHints", "cache", "cookies", or
	// "*".
	ClearSiteDataClears

	// ClearSiteDataFirstParty is ClearSiteDataClears, except that a response
	// that is cross-site to the top-level page clears nothing.
	ClearSiteDataFirstParty
)

// Chromium majors where Clear-Site-Data handling of client hints changes.
const (
	// chromiumClearSiteDataMajor is the first Chromium major whose release
	// source clears client hints on Clear-Site-Data. Earlier releases do not
	// establish the same policy.
	chromiumClearSiteDataMajor = 120

	// chromiumClearSiteDataFirstPartyMajor is the first Chromium major that
	// ignores Clear-Site-Data on responses that are cross-site to the
	// top-level page (clear_site_data_utils.cc).
	chromiumClearSiteDataFirstPartyMajor = 150
)

// ClearSiteData returns how the release applies Clear-Site-Data to the
// client hints an origin asked for. Only Chromium releases send client
// hints; every other release returns ClearSiteDataIgnored.
//
// The caller still applies the rules that depend on the request: the
// response URL must be potentially trustworthy and the request's
// credentials mode must allow credentials for it.
func (e Entry) ClearSiteData() ClearSiteDataRule {
	if e.Family != FamilyChromium {
		return ClearSiteDataIgnored
	}

	major := e.chromiumMajor()

	switch {
	case major >= chromiumClearSiteDataFirstPartyMajor:
		return ClearSiteDataFirstParty

	case major >= chromiumClearSiteDataMajor:
		return ClearSiteDataClears

	default:
		return ClearSiteDataIgnored
	}
}
