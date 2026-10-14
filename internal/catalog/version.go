package catalog

import (
	"cmp"
	"strings"
)

const (
	// maxVersionParts is the most dotted components any cataloged browser
	// uses, as in Chrome's "152.0.7977.85".
	maxVersionParts = 4

	// maxComponentDigits keeps a component well inside int range.
	maxComponentDigits = 9

	// braveProductMajor is the first component of every Brave release.
	braveProductMajor = 1
)

// line identifies a release line: the version prefix whose builds share one
// wire. Chrome, Edge, Firefox, and Firefox ESR lines are majors ("152",
// minor zero); Brave and Safari lines have two components ("1.90", "26.0").
type line struct {
	major int
	minor int
}

// compare orders lines by major, then minor.
func (l line) compare(other line) int {
	if order := cmp.Compare(l.major, other.major); order != 0 {
		return order
	}

	return cmp.Compare(l.minor, other.minor)
}

// versionParts holds the numeric components of a dotted version without
// allocating.
type versionParts struct {
	values [maxVersionParts]int
	count  int
}

// major returns the first component.
func (p versionParts) major() int {
	return p.values[0]
}

// compare orders versions component by component; a version that runs out
// of components first sorts lower.
func (p versionParts) compare(other versionParts) int {
	for i := range min(p.count, other.count) {
		if order := cmp.Compare(p.values[i], other.values[i]); order != 0 {
			return order
		}
	}

	return cmp.Compare(p.count, other.count)
}

// parseVersionParts parses a dotted decimal version such as
// "152.0.7977.85". It rejects empty components, signs, leading zeros, and
// more than four components.
func parseVersionParts(version string) (versionParts, bool) {
	var parts versionParts

	rest := version
	for {
		if parts.count == maxVersionParts {
			return versionParts{}, false
		}

		component, remainder, more := strings.Cut(rest, ".")

		value, ok := parseVersionComponent(component)
		if !ok {
			return versionParts{}, false
		}

		parts.values[parts.count] = value
		parts.count++

		if !more {
			return parts, true
		}

		rest = remainder
	}
}

// parseVersionComponent parses one decimal component of a version.
func parseVersionComponent(component string) (int, bool) {
	if component == "" || len(component) > maxComponentDigits {
		return 0, false
	}

	if len(component) > 1 && component[0] == '0' {
		return 0, false
	}

	value := 0
	for i := range len(component) {
		digit := component[i]
		if digit < '0' || digit > '9' {
			return 0, false
		}

		value = value*10 + int(digit-'0')
	}

	return value, true
}

// releaseLine returns the release line of a cataloged build version.
func releaseLine(browser Browser, version string) (line, bool) {
	parts, ok := parseVersionParts(version)
	if !ok {
		return line{}, false
	}

	switch browser {
	case Brave, Safari:
		if parts.count < 2 {
			return line{}, false
		}

		return line{
			major: parts.values[0],
			minor: parts.values[1],
		}, true

	default:
		return line{major: parts.major()}, true
	}
}

// versionRequest is a parsed Lookup version argument.
type versionRequest struct {
	// release is the requested release line.
	release line

	// anyMinor matches the newest line whose major is release.major, as
	// for the Safari version "26".
	anyMinor bool

	// engineMajor is a Chromium major requested for Brave, such as "148".
	// It is zero when release names a Brave line instead.
	engineMajor int

	// build is a Chrome or Edge full build to report verbatim. It is empty
	// for every other request, including full builds of other browsers,
	// which select their line's newest cataloged build.
	build string
}

// parseVersionRequest parses the version forms Lookup accepts for browser.
// It reports false for malformed versions.
func parseVersionRequest(browser Browser, version string) (versionRequest, bool) {
	parts, ok := parseVersionParts(version)
	if !ok {
		return versionRequest{}, false
	}

	switch browser {
	case Chrome, Edge:
		return chromiumVersionRequest(parts, version)
	case Brave:
		return braveVersionRequest(parts)
	case Firefox, FirefoxESR:
		return firefoxVersionRequest(parts)
	case Safari:
		return safariVersionRequest(parts)
	default:
		return versionRequest{}, false
	}
}

// chromiumVersionRequest accepts a major ("152") or a full four-part build
// ("152.0.7977.85").
func chromiumVersionRequest(parts versionParts, version string) (versionRequest, bool) {
	release := line{major: parts.major()}

	switch parts.count {
	case 1:
		return versionRequest{release: release}, true

	case 4:
		return versionRequest{
			release: release,
			build:   version,
		}, true

	default:
		return versionRequest{}, false
	}
}

// braveVersionRequest accepts a Brave line ("1.90"), any build of a line
// ("1.90.128"), or the Chromium major a Brave line is built on ("148"). A
// build selects its line, so "1.90.5" resolves like "1.90".
func braveVersionRequest(parts versionParts) (versionRequest, bool) {
	if parts.major() != braveProductMajor {
		if parts.count != 1 {
			return versionRequest{}, false
		}

		return versionRequest{engineMajor: parts.major()}, true
	}

	switch parts.count {
	case 2, 3:
		return versionRequest{
			release: line{
				major: braveProductMajor,
				minor: parts.values[1],
			},
		}, true

	default:
		return versionRequest{}, false
	}
}

// firefoxVersionRequest accepts a major ("150") or any build of up to three
// parts ("150.0", "150.0.3", "128.14.0"). A build selects its major, so
// "128.0" resolves like "128".
func firefoxVersionRequest(parts versionParts) (versionRequest, bool) {
	switch parts.count {
	case 1, 2, 3:
		return versionRequest{
			release: line{major: parts.major()},
		}, true

	default:
		return versionRequest{}, false
	}
}

// safariVersionRequest accepts a major ("27"), which selects the newest
// captured release of that major, or an exact release ("27.0"). Minor
// releases are distinct wires and never match each other. Patch builds
// ("26.0.1") are rejected, because Safari reports its full version in the
// User-Agent and only the captured releases are known.
func safariVersionRequest(parts versionParts) (versionRequest, bool) {
	switch parts.count {
	case 1:
		return versionRequest{
			release:  line{major: parts.major()},
			anyMinor: true,
		}, true

	case 2:
		return versionRequest{
			release: line{
				major: parts.values[0],
				minor: parts.values[1],
			},
		}, true

	default:
		return versionRequest{}, false
	}
}

// versionAtLeast reports whether a dotted version is at least minimum. A
// version with more components sorts higher, so "1.69.153" is at least
// "1.69". A malformed version is never at least anything.
func versionAtLeast(version, minimum string) bool {
	parts, ok := parseVersionParts(version)
	if !ok {
		return false
	}

	floor, ok := parseVersionParts(minimum)
	if !ok {
		return false
	}

	return parts.compare(floor) >= 0
}

// completeBuild reports whether version is a full four-part Chromium build,
// such as "152.0.7977.85".
func completeBuild(version string) bool {
	parts, ok := parseVersionParts(version)

	return ok && parts.count == maxVersionParts
}
