package http

import (
	utls "github.com/refraction-networking/utls"
)

// Browser is a well-known browser identifier used by consumers to
// select or categorize fingerprint profiles.
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

// String returns the string representation of the browser.
func (b Browser) String() string {
	return string(b)
}

// Platform is a well-known operating system or device platform used by
// consumers to select or categorize fingerprint profiles.
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
)

// String returns the string representation of the platform.
func (p Platform) String() string {
	return string(p)
}

// Chrome returns a Fingerprint that mimics Google Chrome's TLS and
// HTTP/2 connection behavior.
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
				Weight: 255,
			},
		},
	}
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
				StreamDep: 13,
				Weight:    41,
			},
		},
	}
}

// Safari returns a Fingerprint that mimics Apple Safari's TLS and
// HTTP/2 connection behavior on macOS.
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
				Weight: 254,
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
				Weight: 255,
			},
		},
	}
}

// Brave returns a Fingerprint that mimics the Brave browser's TLS
// and HTTP/2 connection behavior. Brave is Chromium-based and shares
// Chrome's HTTP/2 settings and TLS fingerprint.
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
				Weight: 255,
			},
		},
	}
}
