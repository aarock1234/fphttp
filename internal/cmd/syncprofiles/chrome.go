package main

import (
	"context"
	"fmt"
	"slices"
	"time"
)

const (
	// chromeFeedLimit is the most releases collected for one platform.
	chromeFeedLimit = 1000

	// chromeFeedPageSize is the releases one chromiumdash query returns.
	// chromiumdash answers in time proportional to the page size, so the
	// limit is fetched as concurrent pages rather than in one slow query.
	chromeFeedPageSize = 100
)

// chromeRelease is one entry of a chromiumdash release feed.
type chromeRelease struct {
	Version string `json:"version"`

	// Time is the publication time in Unix milliseconds.
	Time int64 `json:"time"`
}

// chromePlatform names the chromiumdash feed of one platform.
type chromePlatform struct {
	feedName string
	platform platform
}

// chromePlatforms lists the platforms whose Chrome builds embed their own
// Chromium network stack.
var chromePlatforms = []chromePlatform{
	{
		feedName: "Windows",
		platform: platformWindows,
	},
	{
		feedName: "Mac",
		platform: platformMac,
	},
	{
		feedName: "Linux",
		platform: platformLinux,
	},
	{
		feedName: "Android",
		platform: platformAndroid,
	},
}

// chrome collects Stable channel Chrome releases from chromiumdash. Early
// Stable builds are published on the Stable channel and count as stable.
func (c *collector) chrome(ctx context.Context) ([]release, error) {
	perPlatform, err := mapConcurrently(ctx, chromePlatforms, c.chromePlatform)
	if err != nil {
		return nil, err
	}

	return slices.Concat(perPlatform...), nil
}

// chromePlatform collects the Stable channel releases of one platform.
func (c *collector) chromePlatform(ctx context.Context, target chromePlatform) ([]release, error) {
	entries, err := c.chromeFeed(ctx, target)
	if err != nil {
		return nil, err
	}

	if err := c.checkChromeFeedReach(target, entries); err != nil {
		return nil, err
	}

	var releases []release
	for _, entry := range entries {
		released := time.UnixMilli(entry.Time).UTC()
		if !c.window.includes(released) || !numericVersion(entry.Version) {
			continue
		}

		releases = append(releases, release{
			browser:  browserChrome,
			platform: target.platform,
			version:  entry.Version,
			engine:   entry.Version,
			released: released,
		})
	}

	return releases, nil
}

// chromeFeed returns the newest chromeFeedLimit Stable releases of one
// platform, newest first, fetched as concurrent pages.
func (c *collector) chromeFeed(ctx context.Context, target chromePlatform) ([]chromeRelease, error) {
	offsets := make([]int, 0, chromeFeedLimit/chromeFeedPageSize)
	for offset := 0; offset < chromeFeedLimit; offset += chromeFeedPageSize {
		offsets = append(offsets, offset)
	}

	pages, err := mapConcurrently(ctx, offsets, func(ctx context.Context, offset int) ([]chromeRelease, error) {
		pageURL := fmt.Sprintf(
			"https://chromiumdash.appspot.com/fetch_releases?channel=Stable&num=%d&offset=%d&platform=%s",
			chromeFeedPageSize,
			offset,
			target.feedName,
		)

		return c.fetcher.FetchJSON[[]chromeRelease](ctx, pageURL)
	})
	if err != nil {
		return nil, err
	}

	return slices.Concat(pages...), nil
}

// checkChromeFeedReach fails when a feed that fills chromeFeedLimit does not
// reach back past the start of the window, because older releases would be
// missing.
func (c *collector) checkChromeFeedReach(target chromePlatform, entries []chromeRelease) error {
	if len(entries) < chromeFeedLimit {
		return nil
	}

	oldest := entries[0].Time
	for _, entry := range entries {
		oldest = min(oldest, entry.Time)
	}

	if time.UnixMilli(oldest).Before(c.window.since) {
		return nil
	}

	return fmt.Errorf(
		"chromiumdash %s feed holds %d releases without reaching -since; query each milestone instead",
		target.feedName,
		chromeFeedLimit,
	)
}
