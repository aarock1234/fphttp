package catalog

import (
	utls "github.com/refraction-networking/utls"

	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// Wire is the wire configuration that a span of releases shares: the
// ClientHello, the HTTP/2 connection preface, and the header layout.
//
// Each Wire is built once and shared by every Entry in its span. Its slices,
// map, and HTTP/2 template must never be modified; a caller that wants to
// change them deep-copies them first.
type Wire struct {
	// Name identifies the configuration in diagnostics, such as
	// "chromium-152" or "firefox-android-126".
	Name string

	// NewHello returns a fresh ClientHello for each connection. It is safe
	// for concurrent use, and the caller owns the returned spec.
	NewHello func() (*utls.ClientHelloSpec, error)

	// HTTP2 is the HTTP/2 connection template. HeaderPriority is the
	// priority of a top-level document request. The Settings and
	// InitPriorityFrames slices are shared; consumers deep-copy them.
	HTTP2 fingerprint.HTTP2

	// PseudoHeaderOrder lists the four HTTP/2 request pseudo-header fields
	// in wire order.
	PseudoHeaderOrder []string

	// NavigationOrder lists canonical field names in wire order for
	// top-level page loads and iframes.
	NavigationOrder []string

	// SubresourceOrder lists canonical field names in wire order for fetch,
	// XHR, and subresource requests.
	SubresourceOrder []string

	// WebSocketOrder lists canonical field names in wire order for
	// WebSocket handshakes. It is nil when the browser's handshake was not
	// verified, and SubresourceOrder applies instead.
	WebSocketOrder []string

	// H1HeaderCase maps canonical field names to the browser's HTTP/1.1
	// spelling. It is nil when the browser writes canonical names.
	H1HeaderCase map[string]string

	// Chromium describes the Chromium features the wire was built from. It
	// is nil for other families. It is a description only: NewHello and the
	// Entry methods read a private copy, so changing it changes nothing the
	// catalog produces. It is shared and must not be modified.
	Chromium *ChromiumWire

	// Firefox describes the Firefox features the wire was built from. It is
	// nil for other families. Like Chromium, it is a shared description
	// that the catalog does not read.
	Firefox *FirefoxWire

	// chromiumFeatures is the private copy of Chromium that NewHello and
	// the Entry methods read. It is nil for other families.
	chromiumFeatures *ChromiumWire

	// firefoxFeatures is the private copy of Firefox that NewHello and the
	// Entry methods read. It is nil for other families.
	firefoxFeatures *FirefoxWire
}

// span assigns one wire to an inclusive range of major versions.
type span struct {
	first int
	last  int
	wire  *Wire
}

// wireInSpans returns the wire whose span contains major.
func wireInSpans(spans []span, major int) (*Wire, bool) {
	for _, candidate := range spans {
		if major >= candidate.first && major <= candidate.last {
			return candidate.wire, true
		}
	}

	return nil, false
}

// wireForBuild returns the wire of a generated build on its release line.
// It reports false when no hand-written span or capture covers the build.
func wireForBuild(row build, release line) (*Wire, bool) {
	switch row.browser {
	case Chrome, Edge:
		return chromeWire(row.platform, release.major)

	case Brave:
		engine, ok := parseVersionParts(row.engine)
		if !ok {
			return nil, false
		}

		return braveWire(row.platform, engine.major())

	case Firefox:
		return firefoxWire(row.platform, release.major)

	case FirefoxESR:
		return firefoxESRWire(row.platform, release.major)

	case Safari:
		return safariWire(row.platform, release)

	default:
		return nil, false
	}
}
