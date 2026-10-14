package main

import (
	"context"
	"fmt"
	"time"

	http "github.com/aarock1234/fphttp/v2"
	"github.com/aarock1234/fphttp/v2/browser"
)

func (i *importer) bootstrapChrome(ctx context.Context) ([]browser.Descriptor, error) {
	platforms := []struct {
		name string
		id   http.Platform
	}{
		{
			name: "Windows",
			id:   http.PlatformWindows,
		},
		{
			name: "Mac",
			id:   http.PlatformMac,
		},
		{
			name: "Linux",
			id:   http.PlatformLinux,
		},
		{
			name: "Android",
			id:   http.PlatformAndroid,
		},
	}
	var entries []browser.Descriptor
	for _, platform := range platforms {
		for _, milestone := range []int{144, 146, 150, 152, 155} {
			url := fmt.Sprintf("https://chromiumdash.appspot.com/fetch_releases?channel=Stable&num=1&platform=%s&milestone=%d", platform.name, milestone)
			releases, err := fetchJSON[[]chromeRelease](ctx, i, url)
			if err != nil {
				return nil, err
			}
			for _, release := range releases {
				entries = append(entries, inventoryEntry(http.BrowserChrome, platform.id, release.Version, release.Version, "stable", time.UnixMilli(release.Time), browser.Source{
					URL:      url,
					Revision: release.Hashes.Chromium,
					Note:     "Partial bootstrap inventory of requested Chrome families; the complete importer enumerates every published release.",
				}))
			}
		}
	}

	return entries, nil
}
