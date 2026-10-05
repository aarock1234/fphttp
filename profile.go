package http

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

// Profile returns a versioned baseline for a supported browser and platform.
// It returns nil for unknown identifiers and unsupported combinations, including
// Safari on Windows, Linux, or Android, and Firefox on Android.
//
// Known browsers on iOS and iPadOS select the captured WebKit profile. This
// models their WebKit builds; alternative-engine builds require a custom profile.
// Platform selection does not change the host operating system's TCP stack.
func Profile(browser Browser, platform Platform) *Fingerprint {
	switch browser {
	case BrowserChrome, BrowserEdge, BrowserBrave, BrowserSafari, BrowserFirefox:
	default:
		return nil
	}

	switch platform {
	case PlatformIOS, PlatformIPadOS:
		return SafariIOS()
	case PlatformWindows, PlatformMac, PlatformLinux, PlatformAndroid:
	default:
		return nil
	}

	switch browser {
	case BrowserSafari:
		if platform == PlatformMac {
			return Safari()
		}
	case BrowserFirefox:
		if platform != PlatformAndroid {
			return Firefox()
		}
	case BrowserChrome:
		if platform == PlatformAndroid {
			return ChromeAndroid()
		}
		if platform == PlatformMac {
			return ChromeMac()
		}

		return Chrome()
	case BrowserEdge:
		return Edge()
	case BrowserBrave:
		return Brave()
	}

	return nil
}
