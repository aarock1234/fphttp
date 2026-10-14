package main

import "github.com/aarock1234/fphttp/v2/internal/catalog"

// catalogEntry is one supported release in the -catalog listing.
type catalogEntry struct {
	Browser  catalog.Browser  `json:"browser"`
	Platform catalog.Platform `json:"platform"`
	Version  string           `json:"version"`
	Engine   string           `json:"engine"`
	Released string           `json:"released"`
	Wire     string           `json:"wire"`
}

// catalogEntries lists every supported release in catalog order: by
// browser, platform, and then oldest release first.
func catalogEntries() []catalogEntry {
	var entries []catalogEntry

	for entry := range catalog.Entries() {
		entries = append(entries, catalogEntry{
			Browser:  entry.Browser,
			Platform: entry.Platform,
			Version:  entry.Version,
			Engine:   entry.Engine,
			Released: entry.Released,
			Wire:     entry.Wire.Name,
		})
	}

	return entries
}
