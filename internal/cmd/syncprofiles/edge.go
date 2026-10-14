package main

import (
	"context"
	"fmt"
	"html"
	"regexp"
	"strings"
	"time"

	http "github.com/aarock1234/fphttp/v2"
	"github.com/aarock1234/fphttp/v2/browser"
)

var edgeHeadingPattern = regexp.MustCompile(`(?s)<h2\b[^>]*>(.*?)</h2>`)
var edgeVersionPattern = regexp.MustCompile(`Version\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):\s*([A-Za-z]+\s+[0-9]+,\s+[0-9]{4})(?:\s*\((Stable|Extended\s+Stable)\))?`)
var edgeArchivePattern = regexp.MustCompile(`href="([^"]*microsoft-edge-relnote-archive-stable-channel[^"]*)"`)
var edgeMobileVersionPattern = regexp.MustCompile(`Version ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s*\((Android(?: and iOS)?|iOS)\):\s*([A-Za-z]+\s+[0-9]+,\s+[0-9]{4})`)
var edgeHTMLTagPattern = regexp.MustCompile(`(?s)<[^>]*>`)
var edgeBothChannelsPattern = regexp.MustCompile(`\bstable(?: channel)?\s*(?:and|\(\s*and)\s+extended stable\b|\bextended stable(?: channel)?\s+and\s+stable\b`)
var edgeExtendedChannelPattern = regexp.MustCompile(`\b(?:for|to)\s+(?:the\s+)?extended stable\b|\bextended stable (?:channel|release)\b`)

func (i *importer) edge(ctx context.Context) ([]browser.Descriptor, error) {
	url := "https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnote-stable-channel"
	data, err := i.fetch(ctx, url)
	if err != nil {
		return nil, err
	}
	entries := i.edgeNotes(string(data), url)
	seen := map[string]bool{url: true}
	for _, match := range edgeArchivePattern.FindAllStringSubmatch(string(data), -1) {
		archive := match[1]
		if strings.HasPrefix(archive, "/") {
			archive = "https://learn.microsoft.com" + archive
		}
		if !strings.HasPrefix(archive, "https://learn.microsoft.com/") || seen[archive] {
			continue
		}
		seen[archive] = true
		archiveData, err := i.fetch(ctx, archive)
		if err != nil {
			return nil, err
		}
		entries = append(entries, i.edgeNotes(string(archiveData), archive)...)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("Microsoft release-note format changed: no qualifying releases")
	}
	mobile, err := i.edgeMobile(ctx)
	if err != nil {
		return nil, err
	}
	entries = append(entries, mobile...)

	return entries, nil
}

func (i *importer) edgeMobile(ctx context.Context) ([]browser.Descriptor, error) {
	urls := []string{
		"https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnote-mobile-stable-channel",
		"https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnote-archive-mobile-stable-channel",
	}
	var entries []browser.Descriptor
	for _, url := range urls {
		data, err := i.fetch(ctx, url)
		if err != nil {
			return nil, err
		}
		for _, match := range edgeMobileVersionPattern.FindAllStringSubmatch(string(data), -1) {
			released, err := time.Parse("January 2, 2006", strings.Join(strings.Fields(match[3]), " "))
			if err != nil || !i.includes(released) {
				continue
			}
			var platforms []http.Platform
			if strings.Contains(match[2], "Android") {
				platforms = append(platforms, http.PlatformAndroid)
			}
			if strings.Contains(match[2], "iOS") {
				platforms = append(platforms, http.PlatformIOS, http.PlatformIPadOS)
			}
			for _, platform := range platforms {
				entry := inventoryEntry(http.BrowserEdge, platform, match[1], "", "stable", released, browser.Source{
					URL:  url,
					Note: "Microsoft lists this exact mobile product build and release date for the named mobile operating system; this does not establish its engine build or wire configuration.",
				})
				entry.Limitations = append(entry.Limitations,
					"The listed mobile build does not establish an exact Chromium or Apple OS/WebKit networking build; Apple platform aliases record app availability only.")
				entries = append(entries, entry)
			}
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("Microsoft mobile release-note format changed: no qualifying releases")
	}

	return entries, nil
}

func (i *importer) edgeNotes(data, url string) []browser.Descriptor {
	headings := edgeHeadingPattern.FindAllStringSubmatchIndex(data, -1)
	var entries []browser.Descriptor
	for index, heading := range headings {
		match := edgeVersionPattern.FindStringSubmatch(data[heading[2]:heading[3]])
		if len(match) != 4 {
			continue
		}
		released, err := time.Parse("January 2, 2006", strings.Join(strings.Fields(match[2]), " "))
		if err != nil || !i.includes(released) {
			continue
		}
		end := len(data)
		if index+1 < len(headings) {
			end = headings[index+1][0]
		}
		sectionText := html.UnescapeString(edgeHTMLTagPattern.ReplaceAllString(data[heading[1]:end], " "))
		section := strings.ToLower(strings.Join(strings.Fields(sectionText), " "))
		channels := edgeSectionChannels(match[3], section)
		platforms := []http.Platform{
			http.PlatformWindows,
			http.PlatformMac,
			http.PlatformLinux,
		}
		if strings.Contains(section, "windows down-level extended support") {
			platforms = []http.Platform{http.PlatformWindows}
		}
		for _, channel := range channels {
			for _, platform := range platforms {
				entry := inventoryEntry(http.BrowserEdge, platform, match[1], "", channel, released, browser.Source{
					URL:  url,
					Note: "Microsoft's dated desktop release heading and section channel labels; exact platform delivery and proprietary network configuration require additional evidence.",
				})
				entry.Limitations = append(entry.Limitations,
					"A desktop release-note entry is not an independently verified platform package or Chromium engine mapping.")
				if match[1] == "142.0.3595.157" && released.Format(time.DateOnly) == "2025-01-08" {
					entry.Sources[0].Note += " The archive dates this build January 8, 2025 between late-2025 and January-2026 entries; the catalog preserves that apparent publisher inconsistency rather than claiming independently verified chronology."
				}
				entries = append(entries, entry)
			}
		}
	}

	return entries
}

func edgeSectionChannels(headingChannel, section string) []string {
	if headingChannel != "" {
		return []string{strings.ToLower(strings.Join(strings.Fields(headingChannel), "-"))}
	}
	if edgeBothChannelsPattern.MatchString(section) {
		return []string{"stable", "extended-stable"}
	}
	if edgeExtendedChannelPattern.MatchString(section) {
		return []string{"extended-stable"}
	}

	return []string{"stable"}
}
