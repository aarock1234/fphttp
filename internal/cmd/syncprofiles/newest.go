package main

import (
	"cmp"
	"maps"
	"slices"

	"github.com/aarock1234/fphttp/v2/internal/releaseversion"
)

// buildLine identifies the builds of one browser major version on one
// platform.
type buildLine struct {
	browser  browser
	platform platform
	major    string
}

// newestBuilds keeps the newest build of each browser major version on each
// platform. It returns them in generated table order: by browser, then
// platform, then ascending version.
func newestBuilds(releases []release) []release {
	newest := make(map[buildLine]release)
	for _, candidate := range releases {
		line := buildLine{
			browser:  candidate.browser,
			platform: candidate.platform,
			major:    candidate.major(),
		}

		current, found := newest[line]
		if !found || supersedes(candidate, current) {
			newest[line] = candidate
		}
	}

	builds := slices.Collect(maps.Values(newest))
	slices.SortFunc(builds, compareTableOrder)

	return builds
}

// supersedes reports whether candidate replaces current as the newest build
// of its major version. The higher version wins. A version published more
// than once keeps its earliest date, and the engine settles any remaining tie
// so the result never depends on feed order.
func supersedes(candidate, current release) bool {
	if order := releaseversion.Compare(candidate.version, current.version); order != 0 {
		return order > 0
	}

	if !candidate.released.Equal(current.released) {
		return candidate.released.Before(current.released)
	}

	return candidate.engine > current.engine
}

// compareTableOrder orders builds by browser, then platform, then version.
func compareTableOrder(a, b release) int {
	return cmp.Or(
		cmp.Compare(a.browser, b.browser),
		cmp.Compare(a.platform, b.platform),
		releaseversion.Compare(a.version, b.version),
	)
}
