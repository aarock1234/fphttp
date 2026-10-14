package http

// Browser identifies a browser product.
type Browser string

// Browsers that NewProfile recognizes. Firefox ESR is its own product
// because its releases follow a separate track with a different wire.
const (
	// BrowserChrome is Google Chrome.
	BrowserChrome Browser = "chrome"

	// BrowserEdge is Microsoft Edge.
	BrowserEdge Browser = "edge"

	// BrowserBrave is the Brave browser, versioned by its own release line
	// such as "1.90".
	BrowserBrave Browser = "brave"

	// BrowserFirefox is Mozilla Firefox on the stable release track.
	BrowserFirefox Browser = "firefox"

	// BrowserFirefoxESR is Mozilla Firefox on the Extended Support Release
	// track.
	BrowserFirefoxESR Browser = "firefox-esr"

	// BrowserSafari is Apple Safari.
	BrowserSafari Browser = "safari"
)

// Platform identifies the operating system a browser runs on.
type Platform string

// Platforms that NewProfile recognizes. Recognizing a platform does not mean
// every browser has a profile for it; NewProfile reports
// ErrUnsupportedPlatform for such a pair.
const (
	// PlatformWindows is 64-bit Windows 10 or 11.
	PlatformWindows Platform = "windows"

	// PlatformMac is macOS.
	PlatformMac Platform = "mac"

	// PlatformLinux is 64-bit x86 desktop Linux.
	PlatformLinux Platform = "linux"

	// PlatformAndroid is an Android phone.
	PlatformAndroid Platform = "android"

	// PlatformIOS is an iPhone.
	PlatformIOS Platform = "ios"

	// PlatformIPadOS is an iPad. No browser has a profile for it yet.
	PlatformIPadOS Platform = "ipados"
)

// Version selects a browser release. NewProfile accepts a major version
// such as "152", a full build such as "152.0.7977.85", a Brave line such as
// "1.90", or Latest.
type Version string

// Latest selects the newest release fphttp ships for a browser and platform.
const Latest Version = ""

// displayName returns the product name used by Profile.String, such as
// "Firefox ESR".
func (b Browser) displayName() string {
	switch b {
	case BrowserChrome:
		return "Chrome"
	case BrowserEdge:
		return "Edge"
	case BrowserBrave:
		return "Brave"
	case BrowserFirefox:
		return "Firefox"
	case BrowserFirefoxESR:
		return "Firefox ESR"
	case BrowserSafari:
		return "Safari"
	default:
		return string(b)
	}
}

// displayName returns the operating system name used by Profile.String,
// such as "macOS".
func (p Platform) displayName() string {
	switch p {
	case PlatformWindows:
		return "Windows"
	case PlatformMac:
		return "macOS"
	case PlatformLinux:
		return "Linux"
	case PlatformAndroid:
		return "Android"
	case PlatformIOS:
		return "iOS"
	case PlatformIPadOS:
		return "iPadOS"
	default:
		return string(p)
	}
}
