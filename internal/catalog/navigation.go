package catalog

// Values of the fields browsers add only to navigations.
const (
	// upgradeInsecureRequestsValue is the Upgrade-Insecure-Requests value.
	upgradeInsecureRequestsValue = "1"

	// secFetchUserValue is the Sec-Fetch-User value of a user-activated
	// navigation.
	secFetchUserValue = "?1"
)

// UpgradeInsecureRequests returns the Upgrade-Insecure-Requests value the
// release sends for a request destination (see Accept), or "" when it sends
// none. Chromium and Firefox send "1" on every document and iframe load, on
// http and https alike, and never on subresources.
//
// Safari sends none: its captured navigations carry no
// Upgrade-Insecure-Requests, and subframes, which were not captured, are
// assumed to match.
func (e Entry) UpgradeInsecureRequests(destination string) string {
	if !e.sendsUserNavigationFields() || !parseDestination(destination).navigation() {
		return ""
	}

	return upgradeInsecureRequestsValue
}

// SecFetchUser returns the Sec-Fetch-User value the release sends for a
// request destination (see Accept), or "" when it sends none. Chromium and
// Firefox send "?1" on a user-activated navigation. A top-level page load is
// user-activated by default; an iframe load is not, and subresources never
// carry the field.
//
// Safari sends none: its captured navigations carry no Sec-Fetch-User.
//
// The caller still applies the rules that depend on the request, such as
// sending fetch metadata only to potentially trustworthy URLs.
func (e Entry) SecFetchUser(destination string) string {
	if !e.sendsUserNavigationFields() || parseDestination(destination) != destinationDocument {
		return ""
	}

	return secFetchUserValue
}

// sendsUserNavigationFields reports whether the release's engine sends
// Upgrade-Insecure-Requests and Sec-Fetch-User. Safari sends neither.
func (e Entry) sendsUserNavigationFields() bool {
	return e.Family == FamilyChromium || e.Family == FamilyFirefox
}
