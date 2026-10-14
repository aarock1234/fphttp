package catalog

// chromiumMediaRange is the Range value of Chromium's first request for an
// audio or video resource: every byte from the start
// (HttpByteRange::RightUnbounded at position 0).
const chromiumMediaRange = "bytes=0-"

// Range returns the Range value the release sends for a request destination
// (see Accept), or "" when it sends none.
//
// Chromium's media loader requests audio and video with an open-ended range
// from its read position, "bytes=0-" for the first request of a resource,
// together with its own Accept-Encoding (see AcceptEncoding). Firefox and
// Safari media requests were not traced and keep fphttp v1's behavior of
// sending no Range field. Other destinations never carry one.
func (e Entry) Range(destination string) string {
	if e.Family != FamilyChromium || !parseDestination(destination).media() {
		return ""
	}

	return chromiumMediaRange
}
