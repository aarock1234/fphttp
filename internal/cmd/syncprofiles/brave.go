package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	braveRepository = "brave/brave-browser"

	// braveFirstLine is the oldest release line read from the changelogs.
	// Skipping older lines avoids fetching a release page for each of them.
	braveFirstLine = "1.46"
)

var (
	// braveFirstLineCoverage is the earliest -since date that braveFirstLine
	// covers: Brave 1.45.133, the last release of an older line, shipped on
	// 2022-11-24.
	braveFirstLineCoverage = time.Date(2022, time.November, 25, 0, 0, 0, 0, time.UTC)

	// braveHeadingPattern matches a changelog release heading such as
	// "## [1.97.56](https://github.com/brave/brave-browser/releases/tag/v1.97.56)".
	braveHeadingPattern = regexp.MustCompile(`(?m)^## \[([0-9]+\.[0-9]+\.[0-9]+)\]\(https://github.com/brave/brave-browser/releases/tag/(v[^)]+)\)`)

	// braveChromiumPattern matches the Chromium build named in a changelog
	// section, such as "Upgraded Chromium to 155.0.8059.40".
	braveChromiumPattern = regexp.MustCompile(`Chromium(?:\s+to)?\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
)

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

// braveChangelog is one Brave changelog and the edition its releases belong
// to.
type braveChangelog struct {
	name    string
	edition braveEdition
}

// braveChangelogs lists the changelogs of the desktop and Android browsers.
var braveChangelogs = []braveChangelog{
	{
		name:    "CHANGELOG_DESKTOP.md",
		edition: braveDesktop,
	},
	{
		name:    "CHANGELOG_DESKTOP_ARCHIVE.md",
		edition: braveDesktop,
	},
	{
		name:    "CHANGELOG_ANDROID.md",
		edition: braveAndroid,
	},
}

// braveChangelogEntry is one release section of a Brave changelog.
type braveChangelogEntry struct {
	version string
	tag     string

	// chromium is the Chromium build the section names, or "".
	chromium string

	edition braveEdition
}

// braveLine is the changelog entries of one 1.x release line of one
// edition, newest version first.
type braveLine struct {
	edition braveEdition
	entries []braveChangelogEntry
}

// braveLineKey identifies one release line of one edition.
type braveLineKey struct {
	edition string
	line    string
}

// bravePackage is the part of brave-core's package.json that pins the
// Chromium build.
type bravePackage struct {
	Config struct {
		Projects struct {
			Chrome struct {
				Tag string `json:"tag"`
			} `json:"chrome"`
		} `json:"projects"`
	} `json:"config"`
}

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

// braveChangelogEntries reads every release section of the Brave changelogs.
func (c *collector) braveChangelogEntries(ctx context.Context) ([]braveChangelogEntry, error) {
	perChangelog, err := mapConcurrently(ctx, braveChangelogs, c.braveChangelog)
	if err != nil {
		return nil, err
	}

	entries := slices.Concat(perChangelog...)
	if len(entries) == 0 {
		return nil, errors.New("no release headings in the Brave changelogs; the format may have changed")
	}

	return entries, nil
}

// braveChangelog reads the release sections of one changelog.
func (c *collector) braveChangelog(ctx context.Context, changelog braveChangelog) ([]braveChangelogEntry, error) {
	text, err := c.fetcher.fetchText(ctx, "https://raw.githubusercontent.com/brave/brave-browser/master/"+changelog.name)
	if err != nil {
		return nil, err
	}

	return parseBraveChangelog(text, changelog.edition), nil
}

// parseBraveChangelog returns the stable release sections of a changelog
// from braveFirstLine onward.
func parseBraveChangelog(text string, edition braveEdition) []braveChangelogEntry {
	headings := braveHeadingPattern.FindAllStringSubmatchIndex(text, -1)

	var entries []braveChangelogEntry
	for index, heading := range headings {
		version := text[heading[2]:heading[3]]
		if !strings.HasPrefix(version, "1.") || compareVersions(version, braveFirstLine) < 0 {
			continue
		}

		end := len(text)
		if index+1 < len(headings) {
			end = headings[index+1][0]
		}

		var chromium string
		if match := braveChromiumPattern.FindStringSubmatch(text[heading[1]:end]); match != nil {
			chromium = match[1]
		}

		entries = append(entries, braveChangelogEntry{
			version:  version,
			tag:      text[heading[4]:heading[5]],
			chromium: chromium,
			edition:  edition,
		})
	}

	return entries
}

// braveLines groups changelog entries by edition and 1.x release line, in
// changelog order, with each line's entries ordered newest version first.
func braveLines(entries []braveChangelogEntry) []braveLine {
	positions := make(map[braveLineKey]int)

	var lines []braveLine
	for _, entry := range entries {
		key := braveLineKey{
			edition: entry.edition.name,
			line:    versionPrefix(entry.version, 2),
		}

		position, found := positions[key]
		if !found {
			position = len(lines)
			positions[key] = position

			lines = append(lines, braveLine{edition: entry.edition})
		}

		lines[position].entries = append(lines[position].entries, entry)
	}

	for _, line := range lines {
		slices.SortStableFunc(line.entries, func(a, b braveChangelogEntry) int {
			return compareVersions(b.version, a.version)
		})
	}

	return lines
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
	if isNotFound(err) {
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

// pinBraveEngines sets each build's engine to the Chromium build that
// brave-core pins for it. Without a usable pin a build keeps the Chromium
// build its changelog names; without either it is dropped with a warning.
func (c *collector) pinBraveEngines(ctx context.Context, builds []release) ([]release, error) {
	versions := make([]string, 0, len(builds))
	for _, build := range builds {
		versions = append(versions, build.version)
	}

	slices.Sort(versions)
	versions = slices.Compact(versions)

	pinList, err := mapConcurrently(ctx, versions, c.braveChromiumPin)
	if err != nil {
		return nil, err
	}

	pins := make(map[string]string, len(versions))
	for index, version := range versions {
		pins[version] = pinList[index]
	}

	pinned := make([]release, 0, len(builds))
	for _, build := range builds {
		if pin := pins[build.version]; pin != "" {
			build.engine = pin
		}

		if build.engine == "" {
			slog.Warn("skipping Brave build without a known Chromium build",
				slog.String("version", build.version),
				slog.String("platform", build.platform.String()),
			)

			continue
		}

		pinned = append(pinned, build)
	}

	return pinned, nil
}

// braveChromiumPin returns the exact Chromium build that brave-core pins for
// a Brave version. It returns "" with a warning when brave-core has no tag
// for the version or the tag pins no exact build. Any other failure is
// returned, so a transient outage fails the run instead of dropping builds.
func (c *collector) braveChromiumPin(ctx context.Context, version string) (string, error) {
	packageURL := "https://raw.githubusercontent.com/brave/brave-core/v" + version + "/package.json"

	project, err := c.fetcher.fetchJSON[bravePackage](ctx, packageURL)
	if isNotFound(err) {
		slog.Warn("no brave-core tag for Brave version",
			slog.String("version", version),
		)

		return "", nil
	}

	if err != nil {
		return "", err
	}

	pin := project.Config.Projects.Chrome.Tag
	if !numericVersion(pin) || strings.Count(pin, ".") != 3 {
		slog.Warn("ignoring Brave Chromium pin that is not an exact build",
			slog.String("version", version),
			slog.String("pin", pin),
		)

		return "", nil
	}

	return pin, nil
}
