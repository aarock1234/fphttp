package catalog

import (
	"fmt"
	"slices"
	"sync"
)

// browserOrder lists every recognized browser in catalog order.
var browserOrder = []Browser{
	Chrome,
	Edge,
	Brave,
	Firefox,
	FirefoxESR,
	Safari,
}

// platformOrder lists every recognized platform in catalog order.
var platformOrder = []Platform{
	Windows,
	Mac,
	Linux,
	Android,
	IOS,
	IPadOS,
}

// trackKey identifies one browser on one platform.
type trackKey struct {
	browser  Browser
	platform Platform
}

// track holds the supported releases of one browser on one platform, oldest
// release line first. lines[i] is the release line of entries[i].
type track struct {
	lines   []line
	entries []Entry
}

// index is the catalog organized for lookup. It is built once and never
// modified afterwards.
type index struct {
	// tracks holds every browser and platform with at least one supported
	// release. Track slices share storage with entries.
	tracks map[trackKey]track

	// entries holds every supported release in browser, platform, and
	// release line order.
	entries []Entry
}

// candidate is a supported build before the index groups it.
type candidate struct {
	release line
	parts   versionParts
	entry   Entry
}

// catalogIndex builds the index on first use.
var catalogIndex = sync.OnceValue(buildIndex)

// buildIndex keeps every generated build that has a wire and survives the
// coverage decisions, then groups the newest build of each release line by
// browser and platform.
func buildIndex() *index {
	grouped := make(map[trackKey][]candidate)

	for _, row := range builds {
		supported, ok := supportedCandidate(row)
		if !ok {
			continue
		}

		key := trackKey{
			browser:  row.browser,
			platform: row.platform,
		}

		grouped[key] = append(grouped[key], supported)
	}

	// Every supported entry comes from one build, so entries never grows
	// past len(builds) and the track subslices stay valid.
	result := &index{
		tracks:  make(map[trackKey]track, len(grouped)),
		entries: make([]Entry, 0, len(builds)),
	}

	for _, browser := range browserOrder {
		for _, platform := range platformOrder {
			key := trackKey{
				browser:  browser,
				platform: platform,
			}

			candidates, ok := grouped[key]
			if !ok {
				continue
			}

			result.addTrack(key, candidates)
		}
	}

	return result
}

// supportedCandidate returns the catalog entry for a generated build, or
// false when no wire covers it or a coverage decision drops it.
//
// A malformed generated version is a defect in builds_gen.go, and a
// supported release without a User-Agent is a defect in the hand-written
// tables. Both panic rather than silently shrinking coverage or shipping a
// release that cannot identify itself.
func supportedCandidate(row build) (candidate, bool) {
	parts, ok := parseVersionParts(row.version)
	if !ok {
		panic(fmt.Sprintf("catalog: malformed generated version %q for %s on %s", row.version, row.browser, row.platform))
	}

	release, ok := releaseLine(row.browser, row.version)
	if !ok {
		panic(fmt.Sprintf("catalog: generated version %q for %s on %s has no release line", row.version, row.browser, row.platform))
	}

	wire, ok := wireForBuild(row, release)
	if !ok || dropped(row.browser, row.platform, release) {
		return candidate{}, false
	}

	entry := Entry{
		Browser:  row.browser,
		Platform: row.platform,
		Version:  row.version,
		Engine:   row.engine,
		Released: row.released,
		Family:   familyOf(row.browser),
		Wire:     wire,
	}

	if entry.UserAgent() == "" {
		panic(fmt.Sprintf("catalog: supported release %s %s on %s has no User-Agent", row.browser, row.version, row.platform))
	}

	return candidate{
		release: release,
		parts:   parts,
		entry:   entry,
	}, true
}

// addTrack sorts one track's candidates by release line, keeps the newest
// build of each line, and appends the result to the index.
func (x *index) addTrack(key trackKey, candidates []candidate) {
	slices.SortFunc(candidates, func(a, b candidate) int {
		if order := a.release.compare(b.release); order != 0 {
			return order
		}

		return b.parts.compare(a.parts)
	})

	candidates = slices.CompactFunc(candidates, func(a, b candidate) bool {
		return a.release == b.release
	})

	start := len(x.entries)
	lines := make([]line, 0, len(candidates))

	for _, supported := range candidates {
		lines = append(lines, supported.release)
		x.entries = append(x.entries, supported.entry)
	}

	x.tracks[key] = track{
		lines:   lines,
		entries: x.entries[start:len(x.entries):len(x.entries)],
	}
}

// familyOf returns the engine family of a recognized browser.
func familyOf(browser Browser) Family {
	switch browser {
	case Firefox, FirefoxESR:
		return FamilyFirefox
	case Safari:
		return FamilySafari
	default:
		return FamilyChromium
	}
}
