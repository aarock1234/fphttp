package catalog

import "iter"

// Build is one generated release row of builds_gen.go: the newest published
// build of one browser major version, or Brave or Safari release line, on
// one platform, as the official release feeds list it.
//
// Unlike an Entry, a Build need not be supported. Builds also yields
// releases that no hand-written span or capture covers, such as a major
// newer than every span, and releases a coverage decision drops.
type Build struct {
	// Browser is the browser product.
	Browser Browser

	// Platform is the operating system the release runs on.
	Platform Platform

	// Version is the product build, such as "152.0.7977.85" or Brave
	// "1.90.128".
	Version string

	// Engine is the Chromium build for Chrome and Brave and the Gecko
	// version for Firefox, or empty when the feeds do not state it.
	Engine string

	// Released is the release date as YYYY-MM-DD.
	Released string
}

// Builds yields every generated build in table order, supported or not.
// Tools use it to find releases the hand-written tables do not cover yet;
// Lookup and Entries remain the way to select a supported release.
func Builds() iter.Seq[Build] {
	return func(yield func(Build) bool) {
		for _, row := range builds {
			generated := Build{
				Browser:  row.browser,
				Platform: row.platform,
				Version:  row.version,
				Engine:   row.engine,
				Released: row.released,
			}

			if !yield(generated) {
				return
			}
		}
	}
}
