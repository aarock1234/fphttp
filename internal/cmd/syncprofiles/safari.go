package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	http "github.com/aarock1234/fphttp/v2"
	"github.com/aarock1234/fphttp/v2/browser"
)

type appleReference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

type appleInline struct {
	Text string `json:"text"`
}

type appleDocument struct {
	Abstract   []appleInline             `json:"abstract"`
	References map[string]appleReference `json:"references"`
}

var safariVersionPattern = regexp.MustCompile(`^Safari ([0-9]+(?:\.[0-9]+)*) Release Notes$`)
var appleDatePattern = regexp.MustCompile(`Released\s+([A-Za-z]+\s+[0-9]+,\s+[0-9]{4})`)
var appleAbstractVersionPattern = regexp.MustCompile(`Version\s+([0-9]+(?:\.[0-9]+)*)`)

func (i *importer) safari(ctx context.Context) ([]browser.Descriptor, error) {
	indexURL := "https://developer.apple.com/tutorials/data/documentation/safari-release-notes.json"
	index, err := fetchJSON[appleDocument](ctx, i, indexURL)
	if err != nil {
		return nil, err
	}

	var entries []browser.Descriptor
	for _, reference := range index.References {
		versionMatch := safariVersionPattern.FindStringSubmatch(reference.Title)
		if len(versionMatch) != 2 {
			continue
		}
		url := "https://developer.apple.com/tutorials/data" + reference.URL + ".json"
		document, err := fetchJSON[appleDocument](ctx, i, url)
		if err != nil {
			return nil, err
		}
		var abstract strings.Builder
		for _, inline := range document.Abstract {
			abstract.WriteString(inline.Text)
		}
		dateMatch := appleDatePattern.FindStringSubmatch(abstract.String())
		if len(dateMatch) != 2 {
			continue
		}
		released, err := time.Parse("January 2, 2006", strings.Join(strings.Fields(dateMatch[1]), " "))
		if err != nil || !i.includes(released) {
			continue
		}
		version := versionMatch[1]
		if !strings.Contains(version, ".") {
			version += ".0"
		}
		for _, platform := range []http.Platform{
			http.PlatformMac,
			http.PlatformIOS,
			http.PlatformIPadOS,
		} {
			entry := inventoryEntry(http.BrowserSafari, platform, version, "", "stable", released, browser.Source{
				URL:  "https://developer.apple.com" + reference.URL,
				Note: abstract.String(),
			})
			entry.Limitations = []string{
				"Apple's public WebKit release notes do not establish the complete OS-specific CFNetwork/Network.framework TLS and H2 implementation.",
				"A Safari product version alone does not identify the Apple OS build or frozen User-Agent OS token.",
			}
			abstractVersion := appleAbstractVersionPattern.FindStringSubmatch(abstract.String())
			if len(abstractVersion) == 2 && !strings.Contains(abstractVersion[1], ".") {
				abstractVersion[1] += ".0"
			}
			if len(abstractVersion) == 2 && abstractVersion[1] != version {
				entry.Released = ""
				entry.Limitations = append(entry.Limitations,
					"Apple's document title and abstract name different product versions; the release date is left unknown rather than assigning the conflicting abstract date to this version.")
			}
			entries = append(entries, entry)
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("Apple release-note format changed: no qualifying releases")
	}

	return entries, nil
}
