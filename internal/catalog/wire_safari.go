package catalog

// Safari wires. Safari 26.0 and 27.0 on macOS and Safari 27.0 on iOS send
// the same ClientHello and HTTP/2 preface; the platforms differ only in the
// captured subresource header order.
var (
	// safariMac is Safari 26.0 and 27.0 on macOS. Its subresource order
	// comes from the Safari 27 fetch captures; Safari 26.0.1 was captured
	// only for a navigation, so Safari 26.0 carries the order over from 27.
	safariMac = &Wire{
		Name:              "safari-mac",
		NewHello:          safariHello,
		HTTP2:             safariHTTP2(),
		PseudoHeaderOrder: safariPseudoHeaderOrder,
		NavigationOrder:   safariNavigationOrder,
		SubresourceOrder:  safariMacSubresourceOrder,
	}

	// safariIOS is Safari 27.0 on iPhone.
	safariIOS = &Wire{
		Name:              "safari-ios",
		NewHello:          safariHello,
		HTTP2:             safariHTTP2(),
		PseudoHeaderOrder: safariPseudoHeaderOrder,
		NavigationOrder:   safariNavigationOrder,
		SubresourceOrder:  safariIOSSubresourceOrder,
	}
)

// safariRelease is one captured Safari release on one platform.
type safariRelease struct {
	platform Platform
	release  line
	wire     *Wire
}

// safariReleases lists the only Safari releases with a captured wire. Safari
// minor releases are distinct and never inherit a neighbor's wire, and
// iPadOS has no capture.
var safariReleases = []safariRelease{
	{
		platform: Mac,
		release: line{
			major: 26,
			minor: 0,
		},
		wire: safariMac,
	},
	{
		platform: Mac,
		release: line{
			major: 27,
			minor: 0,
		},
		wire: safariMac,
	},
	{
		platform: IOS,
		release: line{
			major: 27,
			minor: 0,
		},
		wire: safariIOS,
	},
}

// safariWire returns the wire of a captured Safari release on platform.
func safariWire(platform Platform, release line) (*Wire, bool) {
	for _, captured := range safariReleases {
		if captured.platform == platform && captured.release == release {
			return captured.wire, true
		}
	}

	return nil, false
}
