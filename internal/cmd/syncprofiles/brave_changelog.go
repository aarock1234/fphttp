package main

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/aarock1234/fphttp/v2/internal/releaseversion"
)

var (
	// braveHeadingPattern matches a changelog release heading such as
	// "## [1.97.56](https://github.com/brave/brave-browser/releases/tag/v1.97.56)".
	braveHeadingPattern = regexp.MustCompile(`(?m)^## \[([0-9]+\.[0-9]+\.[0-9]+)\]\(https://github.com/brave/brave-browser/releases/tag/(v[^)]+)\)`)

	// braveChromiumPattern matches the Chromium build named in a changelog
	// section, such as "Upgraded Chromium to 155.0.8059.40".
	braveChromiumPattern = regexp.MustCompile(`Chromium(?:\s+to)?\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
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
	text, err := c.fetcher.FetchText(ctx, "https://raw.githubusercontent.com/brave/brave-browser/master/"+changelog.name)
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
		if !strings.HasPrefix(version, "1.") || releaseversion.Compare(version, braveFirstLine) < 0 {
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
			return releaseversion.Compare(b.version, a.version)
		})
	}

	return lines
}
