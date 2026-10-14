package main

import (
	"context"
	"errors"
	"html"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	edgeDesktopNotesURL = "https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnote-stable-channel"

	// edgeNotesHost is the only host whose archive links are followed.
	edgeNotesHost = "learn.microsoft.com"
)

// edgeMobileNotesURLs lists the current and archived mobile release notes.
var edgeMobileNotesURLs = []string{
	"https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnote-mobile-stable-channel",
	"https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnote-archive-mobile-stable-channel",
}

var (
	// edgeHeadingPattern matches each <h2> heading of a release notes page.
	edgeHeadingPattern = regexp.MustCompile(`(?s)<h2\b[^>]*>(.*?)</h2>`)

	// edgeDesktopVersionPattern matches a desktop heading such as
	// "Version 155.0.4283.45: October 08, 2026 (Stable)".
	edgeDesktopVersionPattern = regexp.MustCompile(`Version\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):\s*([A-Za-z]+\s+[0-9]+,\s+[0-9]{4})(?:\s*\((Stable|Extended\s+Stable)\))?`)

	// edgeMobileVersionPattern matches a mobile entry such as
	// "Version 155.0.4283.48 (Android and iOS): October 12, 2026".
	edgeMobileVersionPattern = regexp.MustCompile(`Version ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s*\((Android(?: and iOS)?|iOS)\):\s*([A-Za-z]+\s+[0-9]+,\s+[0-9]{4})`)

	// edgeArchiveLinkPattern matches links to archived desktop release notes.
	edgeArchiveLinkPattern = regexp.MustCompile(`href="([^"]*microsoft-edge-relnote-archive-stable-channel[^"]*)"`)

	// edgeHTMLTagPattern matches one HTML tag, to reduce a section to text.
	edgeHTMLTagPattern = regexp.MustCompile(`(?s)<[^>]*>`)

	// edgeBothChannelsPattern matches section text that announces a build for
	// both the Stable and Extended Stable channels.
	edgeBothChannelsPattern = regexp.MustCompile(`\bstable(?: channel)?\s*(?:and|\(\s*and)\s+extended stable\b|\bextended stable(?: channel)?\s+and\s+stable\b`)

	// edgeExtendedChannelPattern matches section text that announces an
	// Extended Stable build.
	edgeExtendedChannelPattern = regexp.MustCompile(`\b(?:for|to)\s+(?:the\s+)?extended stable\b|\bextended stable (?:channel|release)\b`)
)

// edgeDesktopNote is one dated build heading of the desktop release notes.
type edgeDesktopNote struct {
	version   string
	released  time.Time
	stable    bool
	platforms []platform
}

// edgeDesktop collects Stable channel Edge desktop releases from Microsoft's
// current and archived release notes. Microsoft does not publish the
// Chromium build of an Edge release, so the engine stays empty.
func (c *collector) edgeDesktop(ctx context.Context) ([]release, error) {
	current, err := c.fetcher.FetchText(ctx, edgeDesktopNotesURL)
	if err != nil {
		return nil, err
	}

	archives, err := mapConcurrently(ctx, edgeArchiveURLs(current), c.fetcher.FetchText)
	if err != nil {
		return nil, err
	}

	pages := append([]string{current}, archives...)

	var notes []edgeDesktopNote
	for _, page := range pages {
		notes = append(notes, parseEdgeDesktopNotes(page)...)
	}

	if len(notes) == 0 {
		return nil, errors.New("no dated version headings in the Edge desktop release notes; the page format may have changed")
	}

	var releases []release
	for _, note := range notes {
		if !note.stable || !c.window.includes(note.released) {
			continue
		}

		for _, target := range note.platforms {
			releases = append(releases, release{
				browser:  browserEdge,
				platform: target,
				version:  note.version,
				released: note.released,
			})
		}
	}

	return releases, nil
}

// edgeAndroid collects Edge Android releases from Microsoft's current and
// archived mobile release notes. It skips, with a warning, a release whose
// date it cannot parse.
func (c *collector) edgeAndroid(ctx context.Context) ([]release, error) {
	pages, err := mapConcurrently(ctx, edgeMobileNotesURLs, c.fetcher.FetchText)
	if err != nil {
		return nil, err
	}

	var (
		entries  int
		releases []release
	)

	for _, page := range pages {
		for _, match := range edgeMobileVersionPattern.FindAllStringSubmatch(page, -1) {
			entries++

			if !strings.Contains(match[2], "Android") {
				continue
			}

			released, err := parseLongDate(match[3])
			if err != nil {
				warnUnreadableDate("Edge Android", match[1], err)

				continue
			}

			if !c.window.includes(released) {
				continue
			}

			releases = append(releases, release{
				browser:  browserEdge,
				platform: platformAndroid,
				version:  match[1],
				released: released,
			})
		}
	}

	if entries == 0 {
		return nil, errors.New("no dated versions in the Edge mobile release notes; the page format may have changed")
	}

	return releases, nil
}

// edgeArchiveURLs returns the archived desktop release note pages linked from
// the current page, resolved, without fragments, and sorted.
func edgeArchiveURLs(page string) []string {
	base, err := url.Parse(edgeDesktopNotesURL)
	if err != nil {
		panic("invalid Edge release notes URL: " + err.Error())
	}

	var archives []string
	for _, match := range edgeArchiveLinkPattern.FindAllStringSubmatch(page, -1) {
		link, err := base.Parse(html.UnescapeString(match[1]))
		if err != nil || link.Host != edgeNotesHost {
			continue
		}

		link.Fragment = ""
		archives = append(archives, link.String())
	}

	slices.Sort(archives)

	return slices.Compact(archives)
}

// parseEdgeDesktopNotes returns every dated build heading of a desktop
// release notes page. It skips, with a warning, a heading whose date it
// cannot parse.
func parseEdgeDesktopNotes(page string) []edgeDesktopNote {
	headings := edgeHeadingPattern.FindAllStringSubmatchIndex(page, -1)

	var notes []edgeDesktopNote
	for index, heading := range headings {
		match := edgeDesktopVersionPattern.FindStringSubmatch(page[heading[2]:heading[3]])
		if match == nil {
			continue
		}

		released, err := parseLongDate(match[2])
		if err != nil {
			warnUnreadableDate("Edge desktop", match[1], err)

			continue
		}

		end := len(page)
		if index+1 < len(headings) {
			end = headings[index+1][0]
		}

		section := edgeSectionText(page[heading[1]:end])

		notes = append(notes, edgeDesktopNote{
			version:   match[1],
			released:  released,
			stable:    edgeStableChannel(match[3], section),
			platforms: edgeDesktopPlatforms(section),
		})
	}

	return notes
}

// edgeSectionText returns the lowercase text of a release notes section
// with markup removed and whitespace collapsed.
func edgeSectionText(markup string) string {
	text := html.UnescapeString(edgeHTMLTagPattern.ReplaceAllString(markup, " "))

	return strings.ToLower(strings.Join(strings.Fields(text), " "))
}

// edgeStableChannel reports whether a desktop build shipped on the Stable
// channel. The heading names the channel when present; otherwise the section
// text announces it, defaulting to Stable.
func edgeStableChannel(headingChannel, section string) bool {
	if headingChannel != "" {
		return headingChannel == "Stable"
	}

	if edgeBothChannelsPattern.MatchString(section) {
		return true
	}

	return !edgeExtendedChannelPattern.MatchString(section)
}

// edgeDesktopPlatforms returns the platforms a desktop build shipped on.
// Down-level extended support builds ship only for older Windows versions.
func edgeDesktopPlatforms(section string) []platform {
	if strings.Contains(section, "windows down-level extended support") {
		return []platform{platformWindows}
	}

	return desktopPlatforms
}
