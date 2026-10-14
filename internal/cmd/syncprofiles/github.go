package main

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// releasePageTimePattern matches the publication time on a GitHub release
// page. The first match is the release's own publication time.
var releasePageTimePattern = regexp.MustCompile(`<relative-time\b[^>]*\bdatetime="([^"]+)"`)

// githubReleaseTime reads the publication time of a release from its HTML
// page. A release without a public page, such as a draft, fails with a
// *releasefetch.StatusError for 404 Not Found.
func (c *collector) githubReleaseTime(ctx context.Context, repository, tag string) (time.Time, error) {
	page, err := c.fetcher.Fetch(ctx, "https://github.com/"+repository+"/releases/tag/"+tag)
	if err != nil {
		return time.Time{}, err
	}

	match := releasePageTimePattern.FindSubmatch(page)
	if match == nil {
		return time.Time{}, fmt.Errorf("no publication time on the GitHub release page of %s %s", repository, tag)
	}

	published, err := time.Parse(time.RFC3339, string(match[1]))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse publication time of %s %s: %w", repository, tag, err)
	}

	return published.UTC(), nil
}
