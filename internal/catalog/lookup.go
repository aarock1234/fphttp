package catalog

import (
	"fmt"
	"iter"
	"slices"
)

// Lookup returns the supported release of browser on platform that version
// selects. An empty version selects the newest release.
//
// Accepted version forms:
//   - Chrome and Edge: a major ("152") or a full build ("152.0.7977.85").
//   - Brave: a Brave line ("1.90"), a full Brave build ("1.90.128"), or the
//     Chromium major of a Brave line ("148").
//   - Firefox and Firefox ESR: a major ("150") or a full build ("150.0.3").
//   - Safari: a major ("27") or an exact captured release ("27.0"). Safari
//     reports its full version, so patch builds such as "26.0.1" are not
//     accepted.
//
// A major or line selects its newest cataloged build. A Brave, Firefox, or
// Firefox ESR full build selects the same entry as its line, because the
// catalog describes only the newest build of each line and earlier builds
// can differ on the wire, as Firefox 128.0 and 128.0.3 do.
//
// A Chrome or Edge full build is reported verbatim instead, because builds
// within a Chromium major never differ on the wire. A verbatim build that
// the catalog does not list has an empty Released date.
//
// A version newer than the newest supported release returns the newest entry
// together with an error wrapping ErrVersionTooNew. Other failures return a
// zero Entry and an error wrapping ErrUnknownBrowser, ErrUnknownPlatform,
// ErrUnsupportedPlatform, or ErrUnknownVersion.
func Lookup(browser Browser, platform Platform, version string) (Entry, error) {
	if !slices.Contains(browserOrder, browser) {
		return Entry{}, fmt.Errorf("%w: %q", ErrUnknownBrowser, browser)
	}

	if !slices.Contains(platformOrder, platform) {
		return Entry{}, fmt.Errorf("%w: %q", ErrUnknownPlatform, platform)
	}

	releases, ok := catalogIndex().tracks[trackKey{
		browser:  browser,
		platform: platform,
	}]
	if !ok {
		return Entry{}, fmt.Errorf("%w: %s on %s", ErrUnsupportedPlatform, browser, platform)
	}

	if version == "" {
		return releases.newest(), nil
	}

	request, ok := parseVersionRequest(browser, version)
	if !ok {
		return Entry{}, unknownVersion(browser, platform, version)
	}

	if position, ok := releases.find(request); ok {
		return withBuild(releases.entries[position], request.build), nil
	}

	if releases.newerThanNewest(request) {
		newest := releases.newest()

		return newest, fmt.Errorf("%w: %s %s, using %s", ErrVersionTooNew, browser, version, newest.Version)
	}

	return Entry{}, unknownVersion(browser, platform, version)
}

// Entries yields the newest cataloged build of every supported browser,
// platform, and release line, ordered by browser, platform, and then oldest
// release first. Each call iterates the same immutable catalog.
func Entries() iter.Seq[Entry] {
	return slices.Values(catalogIndex().entries)
}

// unknownVersion reports a version Lookup cannot resolve.
func unknownVersion(browser Browser, platform Platform, version string) error {
	return fmt.Errorf("%w: %s %q on %s", ErrUnknownVersion, browser, version, platform)
}

// newest returns the newest release of the track.
func (t track) newest() Entry {
	return t.entries[len(t.entries)-1]
}

// find returns the position of the release that request selects.
func (t track) find(request versionRequest) (int, bool) {
	switch {
	case request.engineMajor != 0:
		return t.findEngineMajor(request.engineMajor)

	case request.anyMinor:
		return t.findMajor(request.release.major)

	default:
		return slices.BinarySearchFunc(t.lines, request.release, line.compare)
	}
}

// findEngineMajor returns the newest release built on a Chromium major.
func (t track) findEngineMajor(engineMajor int) (int, bool) {
	for position := len(t.entries) - 1; position >= 0; position-- {
		if entryEngineMajor(t.entries[position]) == engineMajor {
			return position, true
		}
	}

	return 0, false
}

// findMajor returns the newest release line with a major version.
func (t track) findMajor(major int) (int, bool) {
	for position := len(t.lines) - 1; position >= 0; position-- {
		if t.lines[position].major == major {
			return position, true
		}
	}

	return 0, false
}

// newerThanNewest reports whether request selects a release newer than the
// newest release in the track.
func (t track) newerThanNewest(request versionRequest) bool {
	newestLine := t.lines[len(t.lines)-1]

	switch {
	case request.engineMajor != 0:
		return request.engineMajor > entryEngineMajor(t.newest())

	case request.anyMinor:
		return request.release.major > newestLine.major

	default:
		return request.release.compare(newestLine) > 0
	}
}

// entryEngineMajor returns the Chromium major of an entry, or zero when its
// engine version is unknown.
func entryEngineMajor(entry Entry) int {
	parts, ok := parseVersionParts(entry.Engine)
	if !ok {
		return 0
	}

	return parts.major()
}

// withBuild reports a requested Chrome or Edge full build verbatim on the
// entry of its major. Every other browser keeps the entry's own build. A
// Chrome build is also its Chromium build; Edge records none.
func withBuild(entry Entry, build string) Entry {
	verbatim := entry.Browser == Chrome || entry.Browser == Edge
	if !verbatim || build == "" || build == entry.Version {
		return entry
	}

	entry.Version = build
	entry.Released = ""

	if entry.Browser == Chrome {
		entry.Engine = build
	}

	return entry
}
