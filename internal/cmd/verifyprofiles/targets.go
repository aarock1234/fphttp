package main

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/aarock1234/fphttp/v2/internal/catalog"
	"github.com/aarock1234/fphttp/v2/internal/releaseversion"
)

// sourceFamily is the browser source a group of releases is derived from.
type sourceFamily string

const (
	// familyChromium is Chrome's source. Edge publishes none, but it uses
	// Chrome's wire for the same Chromium major, so it joins Chrome's group.
	familyChromium sourceFamily = "chromium"

	// familyBrave is Chrome's source at the Chromium build Brave pins, with
	// Brave's feature overrides.
	familyBrave sourceFamily = "brave"

	// familyFirefox is Firefox's source at a stable release tag.
	familyFirefox sourceFamily = "firefox"

	// familyFirefoxESR is Firefox's source at an ESR release tag.
	familyFirefoxESR sourceFamily = "firefox-esr"
)

// targetKey identifies one major of one source family on desktop or
// Android. Desktop platforms share a key because the catalog gives Windows,
// macOS, and Linux the same span tables.
type targetKey struct {
	family  sourceFamily
	android bool

	// major is the Chromium major for Chrome, Edge, and Brave, and the
	// Firefox major otherwise.
	major int
}

// target is one derivation: the representative build whose source is read,
// and every cataloged release whose wire the result must match.
type target struct {
	key targetKey

	// representative is the newest release in the group of the family's
	// own browser, Chrome for familyChromium. Its Version is empty when the
	// group has none, as for an Edge major that Chrome does not list.
	representative catalog.Entry

	// entries are the group's releases on every platform.
	entries []catalog.Entry
}

// collectTargets groups every cataloged release except Safari's by source
// family, platform kind, and major, ordered by family, platform kind, and
// major.
func collectTargets() []target {
	groups := make(map[targetKey]*target)

	for entry := range catalog.Entries() {
		key, ok := targetKeyOf(entry)
		if !ok {
			continue
		}

		group, found := groups[key]
		if !found {
			group = &target{
				key: key,
			}
			groups[key] = group
		}

		group.entries = append(group.entries, entry)

		if representsFamily(entry, key.family) && newerRelease(entry, group.representative) {
			group.representative = entry
		}
	}

	targets := make([]target, 0, len(groups))
	for _, group := range groups {
		targets = append(targets, *group)
	}

	slices.SortFunc(targets, compareTargets)

	return targets
}

// targetKeyOf returns the group of a release, or false for Safari, which has
// no derivable source.
func targetKeyOf(entry catalog.Entry) (targetKey, bool) {
	key := targetKey{
		android: entry.Platform == catalog.Android,
		major:   entry.Major(),
	}

	switch entry.Browser {
	case catalog.Chrome, catalog.Edge:
		key.family = familyChromium

	case catalog.Brave:
		key.family = familyBrave
		key.major = versionMajor(entry.Engine)

	case catalog.Firefox:
		key.family = familyFirefox

	case catalog.FirefoxESR:
		key.family = familyFirefoxESR

	default:
		return targetKey{}, false
	}

	return key, true
}

// representsFamily reports whether entry is a release of the browser whose
// source the family derives from.
func representsFamily(entry catalog.Entry, family sourceFamily) bool {
	switch family {
	case familyChromium:
		return entry.Browser == catalog.Chrome
	case familyBrave:
		return entry.Browser == catalog.Brave
	case familyFirefox:
		return entry.Browser == catalog.Firefox
	case familyFirefoxESR:
		return entry.Browser == catalog.FirefoxESR
	default:
		return false
	}
}

// newerRelease reports whether candidate is a newer build than current, or
// current is still unset.
func newerRelease(candidate, current catalog.Entry) bool {
	return current.Version == "" || releaseversion.Compare(candidate.Version, current.Version) > 0
}

// compareTargets orders targets by family, then desktop before Android,
// then major.
func compareTargets(a, b target) int {
	if order := cmp.Compare(a.key.family, b.key.family); order != 0 {
		return order
	}

	if a.key.android != b.key.android {
		if a.key.android {
			return 1
		}

		return -1
	}

	return cmp.Compare(a.key.major, b.key.major)
}

// platforms lists the distinct platforms of the target's releases, in
// catalog order.
func (t target) platforms() []catalog.Platform {
	var platforms []catalog.Platform

	for _, entry := range t.entries {
		if !slices.Contains(platforms, entry.Platform) {
			platforms = append(platforms, entry.Platform)
		}
	}

	return platforms
}

// name describes the target, such as "chromium 130 desktop" or "brave on
// chromium 148 android".
func (t target) name() string {
	platform := "desktop"
	if t.key.android {
		platform = "android"
	}

	if t.key.family == familyBrave {
		return fmt.Sprintf("brave on chromium %d %s", t.key.major, platform)
	}

	return fmt.Sprintf("%s %d %s", t.key.family, t.key.major, platform)
}

// derivationFinding reports that the target's source could not be derived.
func (t target) derivationFinding(err error) finding {
	subject := t.name()
	if t.representative.Version != "" {
		subject += " (source " + t.representative.Version + ")"
	}

	return finding{
		kind:    findingDerivation,
		subject: subject,
		detail:  err.Error(),
	}
}
