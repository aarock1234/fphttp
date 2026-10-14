package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	http "github.com/aarock1234/fphttp"
	"github.com/aarock1234/fphttp/browser"
)

type githubRelease struct {
	Tag        string    `json:"tag_name"`
	Name       string    `json:"name"`
	Body       string    `json:"body"`
	URL        string    `json:"html_url"`
	Published  time.Time `json:"published_at"`
	Prerelease bool      `json:"prerelease"`
	Draft      bool      `json:"draft"`
	Target     string    `json:"target_commitish"`
	Assets     []struct {
		Name string `json:"name"`
	} `json:"assets"`
}

var chromiumReleasePattern = regexp.MustCompile(`Chromium\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
var productVersionPattern = regexp.MustCompile(`(?:^|[^0-9])([0-9]+(?:\.[0-9]+){1,3})(?:$|[^0-9.])`)

func (i *importer) githubReleases(ctx context.Context, repository string) ([]githubRelease, error) {
	var releases []githubRelease
	for page := 1; page <= 10; page++ {
		url := fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=100&page=%d", repository, page)
		batch, err := fetchJSON[[]githubRelease](ctx, i, url)
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		releases = append(releases, batch...)
		if len(batch) < 100 || batch[len(batch)-1].Published.Before(i.since) {
			return releases, nil
		}
	}

	return releases, nil
}

func (i *importer) githubInventory(ctx context.Context, repository string, browserID http.Browser, platforms []http.Platform) ([]browser.Descriptor, error) {
	releases, err := i.githubReleases(ctx, repository)
	if err != nil {
		return nil, err
	}
	if len(releases) == 1000 && !releases[len(releases)-1].Published.Before(i.since) {
		return nil, fmt.Errorf("GitHub release history for %s reached its 1000-entry limit before the requested cutoff; use a product-owned archive", repository)
	}

	var entries []browser.Descriptor
	for _, release := range releases {
		if release.Prerelease || release.Draft || !i.includes(release.Published) {
			continue
		}
		match := productVersionPattern.FindStringSubmatch(release.Tag)
		if len(match) != 2 || !numericVersion(match[1]) {
			continue
		}
		for _, platform := range platforms {
			entries = append(entries, inventoryEntry(browserID, platform, match[1], "", "stable", release.Published, browser.Source{
				URL:      release.URL,
				Revision: release.Tag,
				Note:     "Product-owned release tag; the product version does not establish its embedded engine or Apple networking build.",
			}))
		}
	}

	return entries, nil
}

func (i *importer) brave(ctx context.Context) ([]browser.Descriptor, error) {
	releases, err := i.githubReleases(ctx, "brave/brave-browser")
	if err != nil {
		return nil, err
	}

	known := make(map[string]githubRelease, len(releases))
	for _, release := range releases {
		known[release.Tag] = release
	}
	type changelog struct {
		name      string
		platforms []http.Platform
	}
	logs := []changelog{
		{
			name:      "CHANGELOG_DESKTOP.md",
			platforms: []http.Platform{http.PlatformWindows, http.PlatformMac, http.PlatformLinux},
		},
		{
			name:      "CHANGELOG_DESKTOP_ARCHIVE.md",
			platforms: []http.Platform{http.PlatformWindows, http.PlatformMac, http.PlatformLinux},
		},
		{
			name:      "CHANGELOG_ANDROID.md",
			platforms: []http.Platform{http.PlatformAndroid},
		},
		{
			name:      "CHANGELOG_iOS.md",
			platforms: []http.Platform{http.PlatformIOS, http.PlatformIPadOS},
		},
	}
	var rows []braveChangelogEntry
	for _, log := range logs {
		url := "https://raw.githubusercontent.com/brave/brave-browser/master/" + log.name
		data, err := i.fetch(ctx, url)
		if err != nil {
			return nil, err
		}
		rows = append(rows, braveChangelogRows(string(data), url, log.platforms)...)
	}
	if err := i.completeBraveReleases(ctx, known, rows); err != nil {
		return nil, err
	}
	var entries []browser.Descriptor
	for _, row := range rows {
		release := known[row.tag]
		if release.Prerelease || release.Draft || !i.includes(release.Published) {
			continue
		}
		engine := row.engine
		if row.platform == http.PlatformIOS || row.platform == http.PlatformIPadOS {
			engine = ""
		}
		entry := inventoryEntry(http.BrowserBrave, row.platform, strings.TrimPrefix(row.tag, "v"), engine, "stable", release.Published, browser.Source{
			URL:      release.URL,
			Revision: row.tag,
			Note:     "Official stable changelog and release publication timestamp; iOS application version does not establish its Apple engine build.",
		})
		entry.Sources = append(entry.Sources, browser.Source{URL: row.source})
		entries = append(entries, entry)
	}

	return entries, nil
}

func (i *importer) completeBraveReleases(ctx context.Context, known map[string]githubRelease, rows []braveChangelogEntry) error {
	missing := make(map[string]bool)
	for _, row := range rows {
		if _, found := known[row.tag]; !found {
			missing[row.tag] = true
		}
	}
	var lock sync.Mutex
	var workers sync.WaitGroup
	semaphore := make(chan struct{}, 8)
	var failures []error
	for tag := range missing {
		semaphore <- struct{}{}
		workers.Go(func() {
			defer func() { <-semaphore }()
			release, err := i.githubReleasePage(ctx, tag)
			lock.Lock()
			defer lock.Unlock()
			if err != nil {
				failures = append(failures, err)
				return
			}
			known[tag] = release
		})
	}
	workers.Wait()
	if len(failures) > 0 {
		return fmt.Errorf("read %d Brave release pages: %w", len(failures), failures[0])
	}

	return nil
}

type braveChangelogEntry struct {
	tag      string
	engine   string
	platform http.Platform
	source   string
}

var braveHeadingPattern = regexp.MustCompile(`(?m)^## \[([0-9]+\.[0-9]+\.[0-9]+)\]\(https://github.com/brave/brave-browser/releases/tag/(v[^)]+)\)`)
var releaseTimePattern = regexp.MustCompile(`<relative-time\b[^>]*\bdatetime="([^"]+)"`)

func braveChangelogRows(data, source string, platforms []http.Platform) []braveChangelogEntry {
	indices := braveHeadingPattern.FindAllStringSubmatchIndex(data, -1)
	var rows []braveChangelogEntry
	for index, match := range indices {
		version := data[match[2]:match[3]]
		parts := strings.Split(version, ".")
		// Stable 1.46 was the release family carried into January 2023.
		if len(parts) != 3 || parts[0] != "1" || !newerVersion(version, "1.45.999") {
			continue
		}
		end := len(data)
		if index+1 < len(indices) {
			end = indices[index+1][0]
		}
		section := data[match[1]:end]
		engine := ""
		engineMatch := chromiumReleasePattern.FindStringSubmatch(section)
		if len(engineMatch) == 2 {
			engine = engineMatch[1]
		}
		for _, platform := range platforms {
			rows = append(rows, braveChangelogEntry{
				tag:      data[match[4]:match[5]],
				engine:   engine,
				platform: platform,
				source:   source,
			})
		}
	}

	return rows
}

func (i *importer) githubReleasePage(ctx context.Context, tag string) (githubRelease, error) {
	url := "https://github.com/brave/brave-browser/releases/tag/" + tag
	data, err := i.fetch(ctx, url)
	if err != nil {
		return githubRelease{}, err
	}
	match := releaseTimePattern.FindSubmatch(data)
	if len(match) != 2 {
		return githubRelease{}, fmt.Errorf("missing GitHub publication timestamp for %s", tag)
	}
	published, err := time.Parse(time.RFC3339, string(match[1]))
	if err != nil {
		return githubRelease{}, fmt.Errorf("parse publication of %s: %w", tag, err)
	}

	return githubRelease{
		Tag:       tag,
		URL:       url,
		Published: published,
	}, nil
}
