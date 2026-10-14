package catalog

const (
	// firstReducedEdgeDesktop is the first Edge desktop major whose
	// User-Agent format is established (reduced by default since 119).
	firstReducedEdgeDesktop = 119

	// firstReducedEdgeAndroid is the first Edge Android major whose
	// User-Agent format is established (reduction policy from 140).
	firstReducedEdgeAndroid = 140

	// unreducedChromeAndroid is the Chrome Android major whose User-Agent
	// still carried the real Android version and device model.
	unreducedChromeAndroid = 109

	// lastUnreducedBraveAndroid is the last Brave Android line (Chromium
	// 114) built before Android User-Agent reduction became the compiled
	// default.
	lastUnreducedBraveAndroid = 52
)

// dropped reports whether a coverage decision excludes a release even though
// a wire span covers it. Each decision drops releases whose User-Agent
// cannot be reproduced exactly.
//
// Releases with no wire at all are excluded earlier, when no span or capture
// matches: iOS and iPadOS for every browser but Safari, Safari on iPadOS,
// and Safari releases other than the captured 26.0 and 27.0 family.
func dropped(browser Browser, platform Platform, release line) bool {
	switch browser {
	case Edge:
		return edgeDropped(platform, release.major)

	case Chrome:
		return platform == Android && release.major == unreducedChromeAndroid

	case Brave:
		return platform == Android && release.minor <= lastUnreducedBraveAndroid

	default:
		return false
	}
}

// edgeDropped reports whether an Edge major predates its established
// User-Agent format on platform.
func edgeDropped(platform Platform, major int) bool {
	if platform == Android {
		return major < firstReducedEdgeAndroid
	}

	return major < firstReducedEdgeDesktop
}
