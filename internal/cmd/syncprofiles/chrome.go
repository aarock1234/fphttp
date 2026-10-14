package main

import (
	"context"
	"fmt"
	"time"

	http "github.com/aarock1234/fphttp/v2"
	"github.com/aarock1234/fphttp/v2/browser"
)

type chromeRelease struct {
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Channel  string `json:"channel"`
	Time     int64  `json:"time"`
	Hashes   struct {
		Chromium string `json:"chromium"`
	} `json:"hashes"`
}

func (i *importer) chrome(ctx context.Context) ([]browser.Descriptor, error) {
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
		{
			name: "iOS",
			id:   http.PlatformIOS,
		},
	}

	var entries []browser.Descriptor
	for _, platform := range platforms {
		channels := []string{"Stable"}
		if platform.id == http.PlatformWindows || platform.id == http.PlatformMac {
			channels = append(channels, "Extended")
		}
		for _, channel := range channels {
			url := "https://chromiumdash.appspot.com/fetch_releases?channel=" + channel + "&num=1000&platform=" + platform.name
			releases, err := fetchJSON[[]chromeRelease](ctx, i, url)
			if err != nil {
				return nil, err
			}
			if len(releases) == 1000 {
				oldest := time.UnixMilli(releases[len(releases)-1].Time)
				if !oldest.Before(i.since) {
					return nil, fmt.Errorf("Chrome %s exceeds API page capacity before cutoff; use milestone pagination", platform.name)
				}
			}
			for _, release := range releases {
				released := time.UnixMilli(release.Time)
				if !i.includes(released) || !numericVersion(release.Version) {
					continue
				}
				engine := release.Version
				if platform.id == http.PlatformIOS {
					engine = ""
				}
				channelName := "stable"
				if channel == "Extended" {
					channelName = "extended-stable"
				}
				entry := inventoryEntry(http.BrowserChrome, platform.id, release.Version, engine, channelName, released, browser.Source{
					URL:      url,
					Revision: release.Hashes.Chromium,
					Note:     "Google ChromeDash published stable release; product version does not establish iOS WebKit/OS configuration.",
				})
				if source, known := chromeAnnouncement(release.Version); known {
					entry.Sources = append(entry.Sources, source)
				}
				entries = append(entries, entry)
				if platform.id == http.PlatformIOS {
					entry.Platform = http.PlatformIPadOS
					entry.ID = string(entry.Browser) + "/ipados/" + entry.Version + "/stable/source-default"
					entries = append(entries, entry)
				}
			}
		}
	}

	return entries, nil
}

// These announcements independently establish that the snapshot's newest early
// Stable builds reached real users while the preceding major was maintained.
func chromeAnnouncement(version string) (browser.Source, bool) {
	var url string
	switch version {
	case "156.0.8078.12", "156.0.8078.13":
		url = "https://chromereleases.googleblog.com/2026/10/early-stable-update-for-desktop.html"
	case "156.0.8078.25":
		url = "https://chromereleases.googleblog.com/2026/10/chrome-for-android-update_01286554645.html"
	case "156.0.8078.33":
		url = "https://chromereleases.googleblog.com/2026/10/chrome-stable-for-ios-update_01885421664.html"
	default:
		return browser.Source{}, false
	}

	return browser.Source{
		URL:  url,
		Note: "Google's announcement confirms publication to Stable users; early Stable remains a published Stable release rather than a future-version alias.",
	}, true
}
