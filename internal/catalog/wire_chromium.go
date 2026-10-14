package catalog

import (
	utls "github.com/refraction-networking/utls"
)

// ChromiumHello selects the uTLS ClientHello preset a Chromium wire starts
// from. The zero value is not a preset.
type ChromiumHello uint8

// Chromium ClientHello presets.
const (
	// ChromiumHelloClassical is uTLS HelloChrome_102: no ECH and no
	// post-quantum key share.
	ChromiumHelloClassical ChromiumHello = iota + 1

	// ChromiumHelloECH is uTLS HelloChrome_120: ECH GREASE without a
	// post-quantum key share.
	ChromiumHelloECH

	// ChromiumHelloKyber is uTLS HelloChrome_120_PQ: ECH GREASE and
	// X25519Kyber768Draft00.
	ChromiumHelloKyber

	// ChromiumHelloMLKEM is uTLS HelloChrome_131: ECH GREASE and
	// X25519MLKEM768.
	ChromiumHelloMLKEM
)

// ChromiumWire describes the network features that a span of Chromium
// releases shares. The package's ChromiumWire values are written by hand
// from Chromium source at the newest stable tag of each major (compiled
// defaults, without field trials) and must not be modified.
type ChromiumWire struct {
	// Name identifies the configuration, such as "chromium-152".
	Name string

	// Hello is the uTLS preset the ClientHello starts from.
	Hello ChromiumHello

	// Shuffle permutes the ClientHello extensions on every connection
	// (PermuteTLSExtensions, enabled from 111).
	Shuffle bool

	// NewALPS replaces the ALPS extension with its new code point
	// (UseNewAlpsCodepointHttp2).
	NewALPS bool

	// MLDSA prepends ML-DSA-44, ML-DSA-65, and ML-DSA-87 to the signature
	// algorithms.
	MLDSA bool

	// SignatureGREASE prepends a GREASE value to the signature algorithms,
	// ahead of ML-DSA.
	SignatureGREASE bool

	// TrustAnchorIDs lists the Trust Anchor IDs extension values, sorted
	// bytewise. Empty omits the extension.
	TrustAnchorIDs [][]byte

	// MaxConcurrentStreams is sent as the third SETTINGS parameter when
	// non-zero (1000 through Chromium 116).
	MaxConcurrentStreams uint32

	// PriorityHeader reports that HTTP/2 requests carry the extensible
	// Priority field (from Chromium 124). It does not change the
	// ClientHello or the connection preface.
	PriorityHeader bool
}

// Chromium wires, named after the first Chrome major that shipped them.
var (
	// chromium108 is the classical hello in fixed extension order with
	// MAX_CONCURRENT_STREAMS 1000.
	chromium108 = newChromiumWire(&ChromiumWire{
		Name:                 "chromium-108",
		Hello:                ChromiumHelloClassical,
		MaxConcurrentStreams: 1000,
	})

	// chromium111 starts shuffling extensions.
	chromium111 = newChromiumWire(&ChromiumWire{
		Name:                 "chromium-111",
		Hello:                ChromiumHelloClassical,
		Shuffle:              true,
		MaxConcurrentStreams: 1000,
	})

	// chromium117 stops sending MAX_CONCURRENT_STREAMS.
	chromium117 = newChromiumWire(&ChromiumWire{
		Name:    "chromium-117",
		Hello:   ChromiumHelloClassical,
		Shuffle: true,
	})

	// chromium119 adds ECH GREASE.
	chromium119 = newChromiumWire(&ChromiumWire{
		Name:    "chromium-119",
		Hello:   ChromiumHelloECH,
		Shuffle: true,
	})

	// chromium124 adds the X25519Kyber768 key share on desktop and the
	// HTTP/2 Priority field.
	chromium124 = newChromiumWire(&ChromiumWire{
		Name:           "chromium-124",
		Hello:          ChromiumHelloKyber,
		Shuffle:        true,
		PriorityHeader: true,
	})

	// chromiumAndroid124 is Android before post-quantum key agreement
	// (PostQuantumKyber stayed off on Android until 133): ECH GREASE and the
	// HTTP/2 Priority field.
	chromiumAndroid124 = newChromiumWire(&ChromiumWire{
		Name:           "chromium-android-124",
		Hello:          ChromiumHelloECH,
		Shuffle:        true,
		PriorityHeader: true,
	})

	// chromium131 replaces Kyber with X25519MLKEM768.
	chromium131 = newChromiumWire(&ChromiumWire{
		Name:           "chromium-131",
		Hello:          ChromiumHelloMLKEM,
		Shuffle:        true,
		PriorityHeader: true,
	})

	// chromium135 moves ALPS to its new code point.
	chromium135 = newChromiumWire(&ChromiumWire{
		Name:           "chromium-135",
		Hello:          ChromiumHelloMLKEM,
		Shuffle:        true,
		NewALPS:        true,
		PriorityHeader: true,
	})

	// chromium150 adds ML-DSA signature algorithms.
	chromium150 = newChromiumWire(&ChromiumWire{
		Name:           "chromium-150",
		Hello:          ChromiumHelloMLKEM,
		Shuffle:        true,
		NewALPS:        true,
		MLDSA:          true,
		PriorityHeader: true,
	})

	// chromium152 adds signature algorithm GREASE and 32 Trust Anchor
	// IDs.
	chromium152 = newChromiumWire(&ChromiumWire{
		Name:            "chromium-152",
		Hello:           ChromiumHelloMLKEM,
		Shuffle:         true,
		NewALPS:         true,
		MLDSA:           true,
		SignatureGREASE: true,
		TrustAnchorIDs:  trustAnchorIDs152,
		PriorityHeader:  true,
	})

	// chromium153 sends the 28 Trust Anchor IDs left in the Chrome
	// Root Store.
	chromium153 = newChromiumWire(&ChromiumWire{
		Name:            "chromium-153",
		Hello:           ChromiumHelloMLKEM,
		Shuffle:         true,
		NewALPS:         true,
		MLDSA:           true,
		SignatureGREASE: true,
		TrustAnchorIDs:  trustAnchorIDs153,
		PriorityHeader:  true,
	})

	// brave152 is Brave from Chromium 152, which disables Trust Anchor
	// IDs and so sends none.
	brave152 = newChromiumWire(&ChromiumWire{
		Name:            "brave-152",
		Hello:           ChromiumHelloMLKEM,
		Shuffle:         true,
		NewALPS:         true,
		MLDSA:           true,
		SignatureGREASE: true,
		PriorityHeader:  true,
	})
)

// chromeDesktopSpans assigns wires to Chrome majors on Windows, macOS, and
// Linux. Edge uses the same table for the same major, and Brave uses it for
// its Chromium major.
//
// Corrected against Chromium source: 130 still sent Kyber (UseMLKEM was off),
// and 138 to 141 kept ML-KEM and the new ALPS code point.
var chromeDesktopSpans = []span{
	{
		first: 108,
		last:  110,
		wire:  chromium108,
	},
	{
		first: 111,
		last:  116,
		wire:  chromium111,
	},
	{
		first: 117,
		last:  118,
		wire:  chromium117,
	},
	{
		first: 119,
		last:  123,
		wire:  chromium119,
	},
	{
		first: 124,
		last:  130,
		wire:  chromium124,
	},
	{
		first: 131,
		last:  134,
		wire:  chromium131,
	},
	{
		first: 135,
		last:  149,
		wire:  chromium135,
	},
	{
		first: 150,
		last:  151,
		wire:  chromium150,
	},
	{
		first: 152,
		last:  152,
		wire:  chromium152,
	},
	{
		first: 153,
		last:  156,
		wire:  chromium153,
	},
}

// chromeAndroidSpans assigns wires to Chrome majors on Android. Android kept
// post-quantum key agreement off until 133.
var chromeAndroidSpans = []span{
	{
		first: 109,
		last:  110,
		wire:  chromium108,
	},
	{
		first: 111,
		last:  116,
		wire:  chromium111,
	},
	{
		first: 117,
		last:  118,
		wire:  chromium117,
	},
	{
		first: 119,
		last:  123,
		wire:  chromium119,
	},
	{
		first: 124,
		last:  132,
		wire:  chromiumAndroid124,
	},
	{
		first: 133,
		last:  134,
		wire:  chromium131,
	},
	{
		first: 135,
		last:  149,
		wire:  chromium135,
	},
	{
		first: 150,
		last:  151,
		wire:  chromium150,
	},
	{
		first: 152,
		last:  152,
		wire:  chromium152,
	},
	{
		first: 153,
		last:  156,
		wire:  chromium153,
	},
}

// braveOverrideSpans replaces the Chrome wire for Brave by Chromium major.
var braveOverrideSpans = []span{
	{
		first: 152,
		last:  156,
		wire:  brave152,
	},
}

// chromeWire returns the wire of a Chrome or Edge major on platform.
func chromeWire(platform Platform, major int) (*Wire, bool) {
	switch platform {
	case Windows, Mac, Linux:
		return wireInSpans(chromeDesktopSpans, major)
	case Android:
		return wireInSpans(chromeAndroidSpans, major)
	default:
		return nil, false
	}
}

// braveWire returns the wire of a Brave release built on a Chromium major.
// Brave follows the Chrome table for its platform except where an override
// span applies.
func braveWire(platform Platform, engineMajor int) (*Wire, bool) {
	wire, ok := chromeWire(platform, engineMajor)
	if !ok {
		return nil, false
	}

	if override, ok := wireInSpans(braveOverrideSpans, engineMajor); ok {
		return override, true
	}

	return wire, true
}

// newChromiumWire builds the shared Wire for a Chromium feature set. The
// ClientHello builder and the Entry methods read a private copy, so writes
// through the exported Wire.Chromium cannot change what the wire sends.
func newChromiumWire(features *ChromiumWire) *Wire {
	private := features.clone()

	return &Wire{
		Name: private.Name,
		NewHello: func() (*utls.ClientHelloSpec, error) {
			return chromiumHello(private)
		},
		HTTP2:             chromiumHTTP2(private),
		PseudoHeaderOrder: chromiumPseudoHeaderOrder,
		NavigationOrder:   chromiumNavigationOrder,
		SubresourceOrder:  chromiumSubresourceOrder,
		H1HeaderCase:      chromiumHeaderCase,
		Chromium:          features,
		chromiumFeatures:  private,
	}
}

// clone returns a copy of w that shares no storage with it.
func (w *ChromiumWire) clone() *ChromiumWire {
	copied := *w
	copied.TrustAnchorIDs = cloneTrustAnchorIDs(w.TrustAnchorIDs)

	return &copied
}
