package main

import (
	"context"
	"errors"
	"strings"
	"time"
)

const (
	firefoxDesktopURL = "https://product-details.mozilla.org/1.0/firefox.json"
	firefoxAndroidURL = "https://product-details.mozilla.org/1.0/mobile_android.json"
)

// mozillaProductDetails is a Mozilla product-details release history keyed
// by release ID, such as "firefox-128.0esr".
type mozillaProductDetails struct {
	Releases map[string]mozillaRelease `json:"releases"`
}

// mozillaRelease is one release of a Mozilla product.
type mozillaRelease struct {
	Version string `json:"version"`
	Product string `json:"product"`

	// Category is "major", "stability", "esr", or "dev" for prereleases.
	Category string `json:"category"`

	Date string `json:"date"`
}

// firefoxDesktop collects Firefox release and ESR builds for desktop
// platforms. An "esr" suffix on the release ID marks an ESR build, which
// keeps its ESR identity even when its number matches a release build.
func (c *collector) firefoxDesktop(ctx context.Context) ([]release, error) {
	history, err := c.fetcher.fetchJSON[mozillaProductDetails](ctx, firefoxDesktopURL)
	if err != nil {
		return nil, err
	}

	if len(history.Releases) == 0 {
		return nil, errors.New("no releases in the Firefox product details; the format may have changed")
	}

	var releases []release
	for id, entry := range history.Releases {
		released, included := c.includedMozillaRelease(entry, "firefox")
		if !included {
			continue
		}

		version := strings.TrimSuffix(entry.Version, "esr")
		if !numericVersion(version) {
			continue
		}

		product := browserFirefox
		if strings.HasSuffix(id, "esr") {
			product = browserFirefoxESR
		}

		for _, target := range desktopPlatforms {
			releases = append(releases, release{
				browser:  product,
				platform: target,
				version:  version,
				engine:   version,
				released: released,
			})
		}
	}

	return releases, nil
}

// firefoxAndroid collects Firefox for Android builds. Only the
// firefox-android product shares its version with Gecko; the earlier Fenix
// and Fennec products have no published engine build and are skipped.
func (c *collector) firefoxAndroid(ctx context.Context) ([]release, error) {
	history, err := c.fetcher.fetchJSON[mozillaProductDetails](ctx, firefoxAndroidURL)
	if err != nil {
		return nil, err
	}

	if len(history.Releases) == 0 {
		return nil, errors.New("no releases in the Firefox Android product details; the format may have changed")
	}

	var releases []release
	for _, entry := range history.Releases {
		released, included := c.includedMozillaRelease(entry, "firefox-android")
		if !included || !numericVersion(entry.Version) {
			continue
		}

		releases = append(releases, release{
			browser:  browserFirefox,
			platform: platformAndroid,
			version:  entry.Version,
			engine:   entry.Version,
			released: released,
		})
	}

	return releases, nil
}

// includedMozillaRelease returns the release date of entry and whether it is
// a published build of product inside the window.
func (c *collector) includedMozillaRelease(entry mozillaRelease, product string) (time.Time, bool) {
	if entry.Product != product || entry.Category == "dev" {
		return time.Time{}, false
	}

	released, err := time.Parse(time.DateOnly, entry.Date)
	if err != nil || !c.window.includes(released) {
		return time.Time{}, false
	}

	return released, true
}
