package http

import (
	utls "github.com/refraction-networking/utls"
)

// Browser is a browser identifier used to select a fingerprint profile.
type Browser string

const (
	// BrowserChrome identifies Google Chrome.
	BrowserChrome Browser = "chrome"

	// BrowserEdge identifies Microsoft Edge.
	BrowserEdge Browser = "edge"

	// BrowserBrave identifies the Brave browser.
	BrowserBrave Browser = "brave"

	// BrowserSafari identifies Apple Safari.
	BrowserSafari Browser = "safari"

	// BrowserFirefox identifies Mozilla Firefox.
	BrowserFirefox Browser = "firefox"
)

// String returns the string form of the browser, satisfying fmt.Stringer.
func (b Browser) String() string {
	return string(b)
}

// Platform is an operating system or device platform used to select
// a fingerprint profile.
type Platform string

const (
	// PlatformWindows identifies Microsoft Windows.
	PlatformWindows Platform = "windows"

	// PlatformMac identifies Apple macOS.
	PlatformMac Platform = "mac"

	// PlatformLinux identifies Linux-based desktop systems.
	PlatformLinux Platform = "linux"

	// PlatformIOS identifies Apple iOS (iPhone).
	PlatformIOS Platform = "ios"

	// PlatformIPadOS identifies Apple iPadOS (iPad).
	PlatformIPadOS Platform = "ipados"

	// PlatformAndroid identifies Android.
	PlatformAndroid Platform = "android"
)

// String returns the string form of the platform, satisfying fmt.Stringer.
func (p Platform) String() string {
	return string(p)
}

// Profile returns the Fingerprint that most closely matches the given
// browser on the given platform. It returns nil if no profile is
// defined for the combination.
//
// On iOS and iPadOS, all browsers use WebKit under Apple's App Store
// rules, so any browser on those platforms resolves to SafariIOS.
func Profile(b Browser, p Platform) *Fingerprint {
	if p == PlatformIOS || p == PlatformIPadOS {
		return SafariIOS()
	}

	switch b {
	case BrowserChrome:
		if p == PlatformAndroid {
			return ChromeAndroid()
		}

		return Chrome()
	case BrowserBrave:
		return Brave()
	case BrowserFirefox:
		return Firefox()
	case BrowserSafari:
		return Safari()
	case BrowserEdge:
		return Edge()
	}

	return nil
}

// Chrome returns a Fingerprint that mimics desktop Google Chrome's TLS
// and HTTP/2 connection behavior.
func Chrome() *Fingerprint {
	return &Fingerprint{
		ClientHelloID: utls.HelloChrome_Auto,
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		H2: H2Fingerprint{
			Settings: []H2Setting{
				{ID: H2SettingHeaderTableSize, Val: 65536},
				{ID: H2SettingEnablePush, Val: 0},
				{ID: H2SettingInitialWindowSize, Val: 6291456},
				{ID: H2SettingMaxHeaderListSize, Val: 262144},
			},
			ConnectionFlow: 15663105,
			HeaderPriority: H2Priority{
				Enabled: true,
				Weight:  255,
			},
		},
	}
}

// ChromeAndroid returns a Fingerprint that mimics Chrome on Android.
// Android Chrome shares desktop Chrome's ClientHello and HTTP/2
// settings in our model; server-side detection that distinguishes
// the two typically relies on the User-Agent, sec-ch-ua-* client
// hints, and viewport, which are header-level concerns configured
// by the caller.
func ChromeAndroid() *Fingerprint {
	return Chrome()
}

// Firefox returns a Fingerprint that mimics Mozilla Firefox's TLS and
// HTTP/2 connection behavior. Firefox sends PRIORITY frames during
// connection initialization to establish a dependency tree.
func Firefox() *Fingerprint {
	return &Fingerprint{
		ClientHelloID: utls.HelloFirefox_Auto,
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		H2: H2Fingerprint{
			Settings: []H2Setting{
				{ID: H2SettingHeaderTableSize, Val: 65536},
				{ID: H2SettingInitialWindowSize, Val: 131072},
				{ID: H2SettingMaxFrameSize, Val: 16384},
			},
			ConnectionFlow: 12517377,
			InitPriorityFrames: []H2PriorityFrame{
				{StreamID: 3, StreamDep: 0, Weight: 200, Exclusive: false},
				{StreamID: 5, StreamDep: 0, Weight: 100, Exclusive: false},
				{StreamID: 7, StreamDep: 0, Weight: 0, Exclusive: false},
				{StreamID: 9, StreamDep: 7, Weight: 0, Exclusive: false},
				{StreamID: 11, StreamDep: 3, Weight: 0, Exclusive: false},
			},
			HeaderPriority: H2Priority{
				Enabled:   true,
				StreamDep: 13,
				Weight:    41,
			},
		},
	}
}

// Safari returns a Fingerprint that mimics desktop Apple Safari's TLS
// and HTTP/2 connection behavior on macOS.
func Safari() *Fingerprint {
	return &Fingerprint{
		ClientHelloID: utls.HelloSafari_Auto,
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		H2: H2Fingerprint{
			Settings: []H2Setting{
				{ID: H2SettingHeaderTableSize, Val: 4096},
				{ID: H2SettingEnablePush, Val: 0},
				{ID: H2SettingInitialWindowSize, Val: 2097152},
				{ID: H2SettingMaxConcurrentStreams, Val: 100},
				{ID: H2SettingEnableConnectProtocol, Val: 1},
			},
			ConnectionFlow: 10485760,
			HeaderPriority: H2Priority{
				Enabled: true,
				Weight:  254,
			},
		},
	}
}

// SafariIOS returns a Fingerprint for Safari on iOS and iPadOS. On
// those platforms every browser (Chrome, Firefox, etc.) uses WebKit
// and produces this same TLS fingerprint.
func SafariIOS() *Fingerprint {
	return &Fingerprint{
		ClientHelloID: utls.HelloIOS_Auto,
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		H2: H2Fingerprint{
			Settings: []H2Setting{
				{ID: H2SettingHeaderTableSize, Val: 4096},
				{ID: H2SettingEnablePush, Val: 0},
				{ID: H2SettingInitialWindowSize, Val: 2097152},
				{ID: H2SettingMaxConcurrentStreams, Val: 100},
			},
			ConnectionFlow: 10485760,
			HeaderPriority: H2Priority{
				Enabled: true,
				Weight:  254,
			},
		},
	}
}

// Edge returns a Fingerprint that mimics Microsoft Edge's TLS and
// HTTP/2 connection behavior. Edge is Chromium-based and shares
// Chrome's HTTP/2 settings; only the TLS ClientHello differs.
func Edge() *Fingerprint {
	return &Fingerprint{
		ClientHelloID: utls.HelloEdge_Auto,
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		H2: H2Fingerprint{
			Settings: []H2Setting{
				{ID: H2SettingHeaderTableSize, Val: 65536},
				{ID: H2SettingEnablePush, Val: 0},
				{ID: H2SettingInitialWindowSize, Val: 6291456},
				{ID: H2SettingMaxHeaderListSize, Val: 262144},
			},
			ConnectionFlow: 15663105,
			HeaderPriority: H2Priority{
				Enabled: true,
				Weight:  255,
			},
		},
	}
}

// Brave returns a Fingerprint that mimics the Brave browser's TLS
// and HTTP/2 connection behavior. Brave is Chromium-based and shares
// Chrome's TLS fingerprint and HTTP/2 settings.
func Brave() *Fingerprint {
	return &Fingerprint{
		ClientHelloID: utls.HelloChrome_Auto,
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		H2: H2Fingerprint{
			Settings: []H2Setting{
				{ID: H2SettingHeaderTableSize, Val: 65536},
				{ID: H2SettingEnablePush, Val: 0},
				{ID: H2SettingInitialWindowSize, Val: 6291456},
				{ID: H2SettingMaxHeaderListSize, Val: 262144},
			},
			ConnectionFlow: 15663105,
			HeaderPriority: H2Priority{
				Enabled: true,
				Weight:  255,
			},
		},
	}
}
