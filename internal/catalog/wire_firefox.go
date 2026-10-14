package catalog

import (
	"slices"

	utls "github.com/refraction-networking/utls"
)

// FirefoxWire describes the network features that a span of Firefox
// releases shares. The package's FirefoxWire values are written by hand from
// Firefox and NSS preference defaults at the newest build of each major and
// must not be modified.
type FirefoxWire struct {
	// Name identifies the configuration, such as "firefox-135".
	Name string

	// Android selects GeckoView's HTTP/2 preferences, which shrink
	// HEADER_TABLE_SIZE to 4096 and INITIAL_WINDOW_SIZE to 32768.
	Android bool

	// ECH keeps the GREASE Encrypted Client Hello extension.
	ECH bool

	// MLKEM prepends X25519MLKEM768 to the supported groups and key shares.
	MLKEM bool

	// SCT adds the signed certificate timestamp extension after delegated
	// credentials.
	SCT bool

	// FFDHE keeps the FFDHE2048 and FFDHE3072 groups.
	FFDHE bool

	// DisabledCiphers lists cipher suites removed from the uTLS Firefox 120
	// list.
	DisabledCiphers []uint16

	// CertCompression lists the certificate compression algorithms the
	// ClientHello advertises. Empty omits the extension.
	CertCompression []utls.CertCompressionAlgo

	// LegacyTree uses the RFC 7540 dependency tree: six PRIORITY frames
	// after the preface, the first request on stream 15, and HEADERS that
	// depend on a class group. Every legacy-tree release also allowed server
	// push by default and so omitted ENABLE_PUSH. The transport cannot
	// accept push, so these wires send what Firefox sends with the push
	// preference off: ENABLE_PUSH 0 and MAX_CONCURRENT_STREAMS 0.
	LegacyTree bool

	// NoRFC7540Priorities sends SETTINGS_NO_RFC7540_PRIORITIES 1. It only
	// applies without the legacy tree. Firefox still sets the PRIORITY flag
	// on every HEADERS frame, so the HTTP/2 template pairs the setting with
	// an enabled HeaderPriority.
	NoRFC7540Priorities bool
}

// firefoxCertCompression is the certificate compression list Firefox has
// advertised since 132: zlib, brotli, and zstd.
var firefoxCertCompression = []utls.CertCompressionAlgo{
	utls.CertCompressionZlib,
	utls.CertCompressionBrotli,
	utls.CertCompressionZstd,
}

// Cipher suites later Firefox releases stop offering.
var (
	// firefoxDisabledCiphers150 drops ECDHE-ECDSA-AES128-SHA.
	firefoxDisabledCiphers150 = []uint16{
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	}

	// firefoxDisabledCiphers154 also drops ECDHE-ECDSA-AES256-SHA.
	firefoxDisabledCiphers154 = []uint16{
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	}
)

// Desktop Firefox wires (Windows, macOS, Linux), named after the first
// stable major that shipped them. The IDs in parentheses are the
// configuration IDs of the v2 design spec.
var (
	// firefox108 (F8) has no ECH and uses the legacy priority tree. Firefox
	// ESR 102 and 115 share it.
	firefox108 = newFirefoxWire(&FirefoxWire{
		Name:       "firefox-108",
		FFDHE:      true,
		LegacyTree: true,
	})

	// firefox119 (F0) adds ECH GREASE.
	//
	// Stable 128 resolves to 128.0.3, which restored the legacy tree.
	// Firefox 128.0 and 128.0.2 sent no tree, NO_RFC7540_PRIORITIES 1, and
	// neither ENABLE_PUSH nor MAX_CONCURRENT_STREAMS. The catalog does not
	// describe those builds: Lookup resolves every 128 build to 128.0.3.
	firefox119 = newFirefoxWire(&FirefoxWire{
		Name:       "firefox-119",
		ECH:        true,
		FFDHE:      true,
		LegacyTree: true,
	})

	// firefox132 (F12) drops the legacy tree, adds ML-KEM and certificate
	// compression, and is the only stable major that sends
	// NO_RFC7540_PRIORITIES.
	//
	// Firefox 132 really sends both NO_RFC7540_PRIORITIES 1 and HEADERS
	// frames with the PRIORITY flag set: the setting only stops the legacy
	// tree, and Http2StreamBase writes the flag on every first HEADERS
	// frame. fingerprint.HTTP2.Validate must therefore accept an enabled
	// HeaderPriority together with the setting, while still rejecting
	// InitPriorityFrames with it.
	firefox132 = newFirefoxWire(&FirefoxWire{
		Name:                "firefox-132",
		ECH:                 true,
		MLKEM:               true,
		FFDHE:               true,
		CertCompression:     firefoxCertCompression,
		NoRFC7540Priorities: true,
	})

	// firefox133 (F3) stops sending NO_RFC7540_PRIORITIES.
	firefox133 = newFirefoxWire(&FirefoxWire{
		Name:            "firefox-133",
		ECH:             true,
		MLKEM:           true,
		FFDHE:           true,
		CertCompression: firefoxCertCompression,
	})

	// firefox135 (F10) adds the SCT extension. Firefox ESR 140 shares it.
	firefox135 = newFirefoxWire(&FirefoxWire{
		Name:            "firefox-135",
		ECH:             true,
		MLKEM:           true,
		SCT:             true,
		FFDHE:           true,
		CertCompression: firefoxCertCompression,
	})

	// firefox150 (F11) drops ECDHE-ECDSA-AES128-SHA. Firefox ESR 153
	// shares it.
	firefox150 = newFirefoxWire(&FirefoxWire{
		Name:            "firefox-150",
		ECH:             true,
		MLKEM:           true,
		SCT:             true,
		FFDHE:           true,
		DisabledCiphers: firefoxDisabledCiphers150,
		CertCompression: firefoxCertCompression,
	})

	// firefox154 (F6) also drops ECDHE-ECDSA-AES256-SHA.
	firefox154 = newFirefoxWire(&FirefoxWire{
		Name:            "firefox-154",
		ECH:             true,
		MLKEM:           true,
		SCT:             true,
		FFDHE:           true,
		DisabledCiphers: firefoxDisabledCiphers154,
		CertCompression: firefoxCertCompression,
	})

	// firefox156 (F7) drops the FFDHE groups.
	firefox156 = newFirefoxWire(&FirefoxWire{
		Name:            "firefox-156",
		ECH:             true,
		MLKEM:           true,
		SCT:             true,
		DisabledCiphers: firefoxDisabledCiphers154,
		CertCompression: firefoxCertCompression,
	})

	// firefoxESR128 (F9) is Firefox ESR 128.14, which differs from stable
	// 128: no legacy tree (deps and push off since 128.5esr, no
	// MAX_CONCURRENT_STREAMS since 128.6esr) and no certificate
	// compression.
	//
	// Earlier ESR 128 builds differed: 128.1 to 128.4esr used the legacy
	// tree with push on, 128.5esr sent MAX_CONCURRENT_STREAMS 0, and the
	// document Accept listed image types until 128.7esr. The catalog does
	// not describe them: Lookup resolves every ESR 128 build to 128.14.
	firefoxESR128 = newFirefoxWire(&FirefoxWire{
		Name:  "firefox-esr-128",
		ECH:   true,
		FFDHE: true,
	})
)

// Firefox for Android wires, named after the first Android major that
// shipped them. They share the desktop TLS features of their era but use
// GeckoView's HTTP/2 window settings.
var (
	// firefoxAndroid126 (F0) has ECH GREASE and the legacy priority tree.
	firefoxAndroid126 = newFirefoxWire(&FirefoxWire{
		Name:       "firefox-android-126",
		Android:    true,
		ECH:        true,
		FFDHE:      true,
		LegacyTree: true,
	})

	// firefoxAndroid132 (F1) drops the legacy tree, adds certificate
	// compression, and sends NO_RFC7540_PRIORITIES, without ML-KEM. Like
	// firefox132, it really sends the setting together with HEADERS frames
	// that carry the PRIORITY flag.
	firefoxAndroid132 = newFirefoxWire(&FirefoxWire{
		Name:                "firefox-android-132",
		Android:             true,
		ECH:                 true,
		FFDHE:               true,
		CertCompression:     firefoxCertCompression,
		NoRFC7540Priorities: true,
	})

	// firefoxAndroid133 (F2) stops sending NO_RFC7540_PRIORITIES.
	firefoxAndroid133 = newFirefoxWire(&FirefoxWire{
		Name:            "firefox-android-133",
		Android:         true,
		ECH:             true,
		FFDHE:           true,
		CertCompression: firefoxCertCompression,
	})

	// firefoxAndroid145 (F3) adds ML-KEM.
	firefoxAndroid145 = newFirefoxWire(&FirefoxWire{
		Name:            "firefox-android-145",
		Android:         true,
		ECH:             true,
		MLKEM:           true,
		FFDHE:           true,
		CertCompression: firefoxCertCompression,
	})

	// firefoxAndroid150 (F4) drops ECDHE-ECDSA-AES128-SHA.
	firefoxAndroid150 = newFirefoxWire(&FirefoxWire{
		Name:            "firefox-android-150",
		Android:         true,
		ECH:             true,
		MLKEM:           true,
		FFDHE:           true,
		DisabledCiphers: firefoxDisabledCiphers150,
		CertCompression: firefoxCertCompression,
	})

	// firefoxAndroid154 (F5) also drops ECDHE-ECDSA-AES256-SHA.
	firefoxAndroid154 = newFirefoxWire(&FirefoxWire{
		Name:            "firefox-android-154",
		Android:         true,
		ECH:             true,
		MLKEM:           true,
		FFDHE:           true,
		DisabledCiphers: firefoxDisabledCiphers154,
		CertCompression: firefoxCertCompression,
	})

	// firefoxAndroid155 (F6) adds the SCT extension.
	firefoxAndroid155 = newFirefoxWire(&FirefoxWire{
		Name:            "firefox-android-155",
		Android:         true,
		ECH:             true,
		MLKEM:           true,
		SCT:             true,
		FFDHE:           true,
		DisabledCiphers: firefoxDisabledCiphers154,
		CertCompression: firefoxCertCompression,
	})

	// firefoxAndroid156 (F7) drops the FFDHE groups.
	firefoxAndroid156 = newFirefoxWire(&FirefoxWire{
		Name:            "firefox-android-156",
		Android:         true,
		ECH:             true,
		MLKEM:           true,
		SCT:             true,
		DisabledCiphers: firefoxDisabledCiphers154,
		CertCompression: firefoxCertCompression,
	})
)

// firefoxDesktopSpans assigns wires to stable Firefox majors on Windows,
// macOS, and Linux.
var firefoxDesktopSpans = []span{
	{
		first: 108,
		last:  118,
		wire:  firefox108,
	},
	{
		first: 119,
		last:  131,
		wire:  firefox119,
	},
	{
		first: 132,
		last:  132,
		wire:  firefox132,
	},
	{
		first: 133,
		last:  134,
		wire:  firefox133,
	},
	{
		first: 135,
		last:  149,
		wire:  firefox135,
	},
	{
		first: 150,
		last:  153,
		wire:  firefox150,
	},
	{
		first: 154,
		last:  155,
		wire:  firefox154,
	},
	{
		first: 156,
		last:  158,
		wire:  firefox156,
	},
}

// firefoxAndroidSpans assigns wires to Firefox for Android majors. Majors
// before 126 have no source-derived wire.
var firefoxAndroidSpans = []span{
	{
		first: 126,
		last:  131,
		wire:  firefoxAndroid126,
	},
	{
		first: 132,
		last:  132,
		wire:  firefoxAndroid132,
	},
	{
		first: 133,
		last:  144,
		wire:  firefoxAndroid133,
	},
	{
		first: 145,
		last:  149,
		wire:  firefoxAndroid145,
	},
	{
		first: 150,
		last:  153,
		wire:  firefoxAndroid150,
	},
	{
		first: 154,
		last:  154,
		wire:  firefoxAndroid154,
	},
	{
		first: 155,
		last:  155,
		wire:  firefoxAndroid155,
	},
	{
		first: 156,
		last:  158,
		wire:  firefoxAndroid156,
	},
}

// firefoxESRSpans assigns wires to Firefox ESR majors on Windows, macOS,
// and Linux.
var firefoxESRSpans = []span{
	{
		first: 102,
		last:  102,
		wire:  firefox108,
	},
	{
		first: 115,
		last:  115,
		wire:  firefox108,
	},
	{
		first: 128,
		last:  128,
		wire:  firefoxESR128,
	},
	{
		first: 140,
		last:  140,
		wire:  firefox135,
	},
	{
		first: 153,
		last:  153,
		wire:  firefox150,
	},
}

// firefoxWire returns the wire of a stable Firefox major on platform.
func firefoxWire(platform Platform, major int) (*Wire, bool) {
	switch platform {
	case Windows, Mac, Linux:
		return wireInSpans(firefoxDesktopSpans, major)
	case Android:
		return wireInSpans(firefoxAndroidSpans, major)
	default:
		return nil, false
	}
}

// firefoxESRWire returns the wire of a Firefox ESR major on platform.
func firefoxESRWire(platform Platform, major int) (*Wire, bool) {
	switch platform {
	case Windows, Mac, Linux:
		return wireInSpans(firefoxESRSpans, major)
	default:
		return nil, false
	}
}

// newFirefoxWire builds the shared Wire for a Firefox feature set. The
// ClientHello builder and the Entry methods read a private copy, so writes
// through the exported Wire.Firefox cannot change what the wire sends.
func newFirefoxWire(features *FirefoxWire) *Wire {
	private := features.clone()

	return &Wire{
		Name: private.Name,
		NewHello: func() (*utls.ClientHelloSpec, error) {
			return firefoxHello(private)
		},
		HTTP2:             firefoxHTTP2(private),
		PseudoHeaderOrder: firefoxPseudoHeaderOrder,
		NavigationOrder:   firefoxNavigationOrder,
		SubresourceOrder:  firefoxSubresourceOrder,
		H1HeaderCase:      firefoxHeaderCase,
		Firefox:           features,
		firefoxFeatures:   private,
	}
}

// clone returns a copy of w that shares no storage with it.
func (w *FirefoxWire) clone() *FirefoxWire {
	copied := *w
	copied.DisabledCiphers = slices.Clone(w.DisabledCiphers)
	copied.CertCompression = slices.Clone(w.CertCompression)

	return &copied
}
