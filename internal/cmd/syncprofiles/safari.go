package main

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aarock1234/fphttp/v2/internal/releaseversion"
)

const (
	safariIndexURL = "https://developer.apple.com/tutorials/data/documentation/safari-release-notes.json"

	// appleDocumentationData is the prefix of Apple's JSON documentation
	// pages; a reference URL plus ".json" completes the address.
	appleDocumentationData = "https://developer.apple.com/tutorials/data"
)

var (
	// safariTitlePattern matches a release notes title such as
	// "Safari 26.1 Release Notes". Beta notes do not match.
	safariTitlePattern = regexp.MustCompile(`^Safari ([0-9]+(?:\.[0-9]+)*) Release Notes$`)

	// safariReleasedPattern matches the release date in a notes abstract.
	safariReleasedPattern = regexp.MustCompile(`Released\s+([A-Za-z]+\s+[0-9]+,\s+[0-9]{4})`)

	// safariAbstractVersionPattern matches the version some abstracts state.
	safariAbstractVersionPattern = regexp.MustCompile(`Version\s+([0-9]+(?:\.[0-9]+)*)`)
)

// safariPlatforms lists the platforms whose Safari builds are cataloged.
var safariPlatforms = []platform{
	platformMac,
	platformIOS,
}

// appleDocument is the part of an Apple documentation page this tool reads.
type appleDocument struct {
	Abstract   []appleInline             `json:"abstract"`
	References map[string]appleReference `json:"references"`
}

// appleInline is one inline text run of a documentation abstract.
type appleInline struct {
	Text string `json:"text"`
}

// appleReference is one page referenced by a documentation page.
type appleReference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// safariNote is one Safari release notes page.
type safariNote struct {
	version string
	pageURL string
}

// safari collects every Safari release from Apple's release notes. Apple
// does not publish a separate engine build, so the engine stays empty.
func (c *collector) safari(ctx context.Context) ([]release, error) {
	index, err := c.fetcher.FetchJSON[appleDocument](ctx, safariIndexURL)
	if err != nil {
		return nil, err
	}

	notes := safariNotes(index)
	if len(notes) == 0 {
		return nil, errors.New("no releases in the Safari release notes index; the format may have changed")
	}

	dates, err := mapConcurrently(ctx, notes, c.safariReleaseDate)
	if err != nil {
		return nil, err
	}

	var releases []release
	for index, note := range notes {
		released := dates[index]
		if released.IsZero() || !c.window.includes(released) {
			continue
		}

		for _, target := range safariPlatforms {
			releases = append(releases, release{
				browser:  browserSafari,
				platform: target,
				version:  note.version,
				released: released,
			})
		}
	}

	return releases, nil
}

// safariNotes returns the release notes pages listed by the index, ordered
// by version.
func safariNotes(index appleDocument) []safariNote {
	var notes []safariNote
	for _, reference := range index.References {
		match := safariTitlePattern.FindStringSubmatch(reference.Title)
		if match == nil {
			continue
		}

		notes = append(notes, safariNote{
			version: safariVersion(match[1]),
			pageURL: appleDocumentationData + reference.URL + ".json",
		})
	}

	slices.SortFunc(notes, func(a, b safariNote) int {
		return releaseversion.Compare(a.version, b.version)
	})

	return notes
}

// safariVersion formats a Safari version as Apple names it, appending ".0"
// to a bare major version.
func safariVersion(name string) string {
	if strings.Contains(name, ".") {
		return name
	}

	return name + ".0"
}

// safariReleaseDate returns the release date stated by a notes page. It
// returns the zero time with a warning when the page states no date, or
// when its abstract names a different version than its title.
func (c *collector) safariReleaseDate(ctx context.Context, note safariNote) (time.Time, error) {
	document, err := c.fetcher.FetchJSON[appleDocument](ctx, note.pageURL)
	if err != nil {
		return time.Time{}, err
	}

	var abstract strings.Builder
	for _, inline := range document.Abstract {
		abstract.WriteString(inline.Text)
	}

	text := abstract.String()

	stated := safariAbstractVersionPattern.FindStringSubmatch(text)
	if stated != nil && safariVersion(stated[1]) != note.version {
		slog.Warn("skipping Safari release notes that date another version",
			slog.String("version", note.version),
			slog.String("abstract", text),
		)

		return time.Time{}, nil
	}

	match := safariReleasedPattern.FindStringSubmatch(text)
	if match == nil {
		slog.Warn("skipping Safari release notes without a release date",
			slog.String("version", note.version),
		)

		return time.Time{}, nil
	}

	released, err := parseLongDate(match[1])
	if err != nil {
		slog.Warn("skipping Safari release notes with an unreadable release date",
			slog.String("version", note.version),
			slog.Any("error", err),
		)

		return time.Time{}, nil
	}

	return released, nil
}
