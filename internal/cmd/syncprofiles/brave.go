package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/aarock1234/fphttp/v2/internal/releasefetch"
)

const (
	braveRepository = "brave/brave-browser"

	// braveFirstLine is the oldest release line read from the changelogs.
	// Skipping older lines avoids fetching a release page for each of them.
	braveFirstLine = "1.46"
)

// braveFirstLineCoverage is the earliest -since date that braveFirstLine
// covers: Brave 1.45.133, the last release of an older line, shipped on
// 2022-11-24.
var braveFirstLineCoverage = time.Date(2022, time.November, 25, 0, 0, 0, 0, time.UTC)

// braveEdition is one Brave browser build and the platforms it ships on.
type braveEdition struct {
	name      string
	platforms []platform
}

// The desktop browser ships one build for every desktop platform. The iOS
// browser uses WebKit and is not cataloged.
var (
	braveDesktop = braveEdition{
		name:      "desktop",
		platforms: desktopPlatforms,
	}

	braveAndroid = braveEdition{
		name:      "Android",
		platforms: []platform{platformAndroid},
	}
)

// brave collects the newest stable Brave release of each 1.x line on desktop
// platforms and Android. Its engine is the Chromium build that brave-core
// pins for the release.
func (c *collector) brave(ctx context.Context) ([]release, error) {
	if err := checkBraveCoverage(c.window); err != nil {
		return nil, err
	}

	entries, err := c.braveChangelogEntries(ctx)
	if err != nil {
		return nil, err
	}

	perLine, err := mapConcurrently(ctx, braveLines(entries), c.braveLineReleases)
	if err != nil {
		return nil, err
	}

	return c.pinBraveEngines(ctx, newestBuilds(slices.Concat(perLine...)))
}

// checkBraveCoverage fails when the window starts before the releases that
// the changelogs are read for.
func checkBraveCoverage(w window) error {
	if !w.since.Before(braveFirstLineCoverage) {
		return nil
	}

	return fmt.Errorf(
		"-since must not be before %s: Brave lines older than %s are not read",
		braveFirstLineCoverage.Format(time.DateOnly),
		braveFirstLine,
	)
}

// braveLineReleases returns the newest release of a line published inside
// the window, once for each platform of its edition, or nothing when the line
// has none.
//
// The changelogs list only stable releases, so their GitHub prerelease flag
// is ignored: Brave flags its Android-only stable releases as prereleases.
//
// It dates releases newest version first and so reads only the release pages
// it needs: a release published after the window moves on to the next older
// build, and a release published before it ends the search, since every
// older build of the line predates it too.
func (c *collector) braveLineReleases(ctx context.Context, line braveLine) ([]release, error) {
	for _, entry := range line.entries {
		published, found, err := c.braveReleaseTime(ctx, entry)
		if err != nil {
			return nil, err
		}

		if !found {
			continue
		}

		if published.Before(c.window.since) {
			return nil, nil
		}

		if c.window.includes(published) {
			return braveReleases(entry, published), nil
		}
	}

	return nil, nil
}

// braveReleaseTime reads the publication time of a changelog entry's GitHub
// release. It reports false with a warning when the release has no page, as
// when it is not yet published or its tag was renamed, and fails on any
// other error.
func (c *collector) braveReleaseTime(ctx context.Context, entry braveChangelogEntry) (time.Time, bool, error) {
	published, err := c.githubReleaseTime(ctx, braveRepository, entry.tag)
	if releasefetch.IsNotFound(err) {
		slog.Warn("skipping Brave changelog entry without a GitHub release",
			slog.String("version", entry.version),
			slog.String("tag", entry.tag),
		)

		return time.Time{}, false, nil
	}

	if err != nil {
		return time.Time{}, false, err
	}

	return published, true, nil
}

// braveReleases returns the build of a changelog entry published at
// released, once for each platform of its edition.
func braveReleases(entry braveChangelogEntry, released time.Time) []release {
	releases := make([]release, 0, len(entry.edition.platforms))
	for _, target := range entry.edition.platforms {
		releases = append(releases, release{
			browser:  browserBrave,
			platform: target,
			version:  entry.version,
			engine:   entry.chromium,
			released: released,
		})
	}

	return releases
}
