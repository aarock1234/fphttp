package http

import (
	utls "github.com/refraction-networking/utls"
)

// Chrome returns the Chrome 148 navigation profile captured on Windows.
// Chromium randomizes extension order, GREASE, and ephemeral key material.
func Chrome() *Fingerprint {
	return Chrome148()
}

// Chrome120 uses uTLS's Chrome 120 ClientHello and Chromium HTTP/2 settings.
// Its default priority models a navigation request.
func Chrome120() *Fingerprint {
	return chromiumProfile(utls.HelloChrome_120)
}

// Chrome131 uses the Chrome 131 preset, including the ML-KEM key exchange.
func Chrome131() *Fingerprint {
	return chromiumProfile(utls.HelloChrome_131)
}

// Chrome133 uses the Chrome 133 preset with the updated ALPS extension ID.
func Chrome133() *Fingerprint {
	return chromiumProfile(utls.HelloChrome_133)
}

// Chrome148 matches the observed Chrome 148 TLS parameters and HTTP/2
// connection settings. Its ClientHello has the same parameter set as the
// Chrome 133 preset; randomized extension order is preserved.
// Header ordering and priority model a navigation request, without adding
// browser header values. See Chrome148Fetch for the captured fetch variation.
func Chrome148() *Fingerprint {
	profile := Chrome133()
	profile.HeaderOrder = []string{
		"Host",
		"Connection",
		"Cache-Control",
		"Sec-Ch-Ua",
		"Sec-Ch-Ua-Mobile",
		"Sec-Ch-Ua-Platform",
		"Accept-Language",
		"Dnt",
		"Upgrade-Insecure-Requests",
		"User-Agent",
		"Accept",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Sec-Fetch-User",
		"Sec-Fetch-Dest",
		"Accept-Encoding",
		"If-None-Match",
		"Priority",
	}

	return profile
}

// Chrome148Fetch models the captured same-origin fetch request. Its effective
// priority weight is 220 (wire value 219), compared with 256 for navigation.
// The TLS and connection settings are identical, so callers may instead use
// its HeaderOrder and H2.HeaderPriority as per-request overrides on one client.
func Chrome148Fetch() *Fingerprint {
	profile := Chrome133()
	profile.HeaderOrder = []string{
		"Host",
		"Connection",
		"Pragma",
		"Cache-Control",
		"Sec-Ch-Ua-Platform",
		"Accept-Language",
		"Sec-Ch-Ua",
		"Dnt",
		"User-Agent",
		"Sec-Ch-Ua-Mobile",
		"Accept",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Sec-Fetch-Dest",
		"Accept-Encoding",
		"Priority",
	}
	profile.H2.HeaderPriority.Weight = 219

	return profile
}

// ChromeAndroid uses the current Chromium baseline. Android-specific browser
// headers are supplied by the caller; no Android capture was supplied.
func ChromeAndroid() *Fingerprint {
	return Chrome148()
}

// Edge uses the current Chromium baseline. It does not claim an independently
// captured Edge version. The old HelloEdge_Auto preset selected Edge 85.
func Edge() *Fingerprint {
	return Chrome148()
}

// Brave uses the current Chromium baseline. Brave-specific headers and TLS
// differences in particular builds require a capture or custom profile.
func Brave() *Fingerprint {
	return Chrome148()
}

func chromiumProfile(helloID utls.ClientHelloID) *Fingerprint {
	return &Fingerprint{
		ClientHelloID: helloID,
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		H2: H2Fingerprint{
			Settings: []H2Setting{
				{
					ID:  H2SettingHeaderTableSize,
					Val: 65536,
				},
				{
					ID:  H2SettingEnablePush,
					Val: 0,
				},
				{
					ID:  H2SettingInitialWindowSize,
					Val: 6291456,
				},
				{
					ID:  H2SettingMaxHeaderListSize,
					Val: 262144,
				},
			},
			ConnectionFlow: 15663105,
			HeaderPriority: H2Priority{
				Enabled:   true,
				Exclusive: true,
				Weight:    255,
			},
		},
	}
}
