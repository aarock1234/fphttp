package main

import (
	"context"
	"strings"
	"time"

	http "github.com/aarock1234/fphttp"
	"github.com/aarock1234/fphttp/browser"
)

func (i *importer) firefox(ctx context.Context) ([]browser.Descriptor, error) {
	productURL := "https://product-details.mozilla.org/1.0/firefox.json"
	product, err := fetchJSON[mozillaReleaseHistory](ctx, i, productURL)
	if err != nil {
		return nil, err
	}
	historyURLs := []string{
		"https://product-details.mozilla.org/1.0/firefox_history_major_releases.json",
		"https://product-details.mozilla.org/1.0/firefox_history_stability_releases.json",
	}
	histories := make(map[string]map[string]string, len(historyURLs))
	for _, url := range historyURLs {
		history, err := fetchJSON[map[string]string](ctx, i, url)
		if err != nil {
			return nil, err
		}
		histories[url] = history
	}

	var entries []browser.Descriptor
	for releaseID, release := range product.Releases {
		version := strings.TrimSuffix(release.Version, "esr")
		released, err := time.Parse(time.DateOnly, release.Date)
		if err != nil || !i.includes(released) || !numericVersion(version) ||
			release.Product != "firefox" || release.Category == "dev" {
			continue
		}
		channel := "stable"
		if strings.HasSuffix(releaseID, "esr") {
			channel = "esr"
		}
		sources := []browser.Source{{
			URL:      productURL,
			Revision: releaseID,
			Note:     "Mozilla Ship-It release identifiers distinguish stable and ESR builds, including initial ESR releases sharing a numeric product version.",
		}}
		for _, url := range historyURLs {
			if histories[url][version] == release.Date {
				sources = append(sources, browser.Source{
					URL:  url,
					Note: "Published major or stability history confirms this date; channel identity comes from the keyed Ship-It record.",
				})
			}
		}
		for _, platform := range []http.Platform{
			http.PlatformWindows,
			http.PlatformMac,
			http.PlatformLinux,
		} {
			entry := inventoryEntry(http.BrowserFirefox, platform, version, version, channel, released, sources[0])
			entry.Sources = append(entry.Sources, sources[1:]...)
			entries = append(entries, entry)
		}
	}

	mobile, err := i.firefoxAndroid(ctx)
	if err != nil {
		return nil, err
	}
	entries = append(entries, mobile...)

	return entries, nil
}

type mozillaReleaseHistory struct {
	Releases map[string]struct {
		Version  string `json:"version"`
		Product  string `json:"product"`
		Category string `json:"category"`
		Date     string `json:"date"`
	} `json:"releases"`
}

func (i *importer) firefoxAndroid(ctx context.Context) ([]browser.Descriptor, error) {
	url := "https://product-details.mozilla.org/1.0/mobile_android.json"
	history, err := fetchJSON[mozillaReleaseHistory](ctx, i, url)
	if err != nil {
		return nil, err
	}
	var entries []browser.Descriptor
	for _, release := range history.Releases {
		released, err := time.Parse(time.DateOnly, release.Date)
		if err != nil || !i.includes(released) || !numericVersion(release.Version) || release.Category == "dev" {
			continue
		}
		engine := ""
		if release.Product == "firefox-android" {
			engine = release.Version
		}
		entry := inventoryEntry(http.BrowserFirefox, http.PlatformAndroid, release.Version, engine, "stable", released, browser.Source{
			URL:  url,
			Note: "Mozilla Ship-It published Android release history, including the successor firefox-android product; historical Fenix and Gecko builds use different identifiers.",
		})
		entry.Sources = append(entry.Sources, browser.Source{
			URL:  "https://firefox-source-docs.mozilla.org/mobile/android/shared/versioning.html",
			Note: "The unified Android product uses the shared version file; Android-only patch releases still require their actual source tag.",
		})
		entries = append(entries, entry)
	}

	return entries, nil
}

func (i *importer) firefoxIOS(ctx context.Context) ([]browser.Descriptor, error) {
	return i.githubInventory(ctx, "mozilla-mobile/firefox-ios", http.BrowserFirefox, []http.Platform{
		http.PlatformIOS,
		http.PlatformIPadOS,
	})
}
