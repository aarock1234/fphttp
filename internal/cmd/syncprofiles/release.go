package main

import "time"

// browser identifies a browser product. Declaration order is the order of
// the generated table.
type browser int

const (
	browserChrome browser = iota
	browserEdge
	browserBrave
	browserFirefox
	browserFirefoxESR
	browserSafari
)

// browserIdentifiers maps each browser to its constant in internal/catalog.
var browserIdentifiers = [...]string{
	browserChrome:     "Chrome",
	browserEdge:       "Edge",
	browserBrave:      "Brave",
	browserFirefox:    "Firefox",
	browserFirefoxESR: "FirefoxESR",
	browserSafari:     "Safari",
}

// String returns the internal/catalog constant that names b.
func (b browser) String() string {
	return browserIdentifiers[b]
}

// platform identifies an operating system. Declaration order is the order of
// the generated table.
type platform int

const (
	platformWindows platform = iota
	platformMac
	platformLinux
	platformAndroid
	platformIOS
)

// platformIdentifiers maps each platform to its constant in internal/catalog.
var platformIdentifiers = [...]string{
	platformWindows: "Windows",
	platformMac:     "Mac",
	platformLinux:   "Linux",
	platformAndroid: "Android",
	platformIOS:     "IOS",
}

// String returns the internal/catalog constant that names p.
func (p platform) String() string {
	return platformIdentifiers[p]
}

// desktopPlatforms lists the platforms that share one desktop build.
var desktopPlatforms = []platform{
	platformWindows,
	platformMac,
	platformLinux,
}

// release is one published browser build on one platform.
type release struct {
	browser  browser
	platform platform

	// version is the product build, such as "152.0.7977.85" or "1.90.128".
	version string

	// engine is the Chromium or Gecko build the product embeds, or "" when
	// the vendor does not publish it.
	engine string

	released time.Time
}

// major returns the version line that groups builds of one major version:
// the first version component, or the first two for Brave ("1.90") and
// Safari ("26.1"), whose minor versions are separate releases.
func (r release) major() string {
	switch r.browser {
	case browserBrave, browserSafari:
		return versionPrefix(r.version, 2)
	default:
		return versionPrefix(r.version, 1)
	}
}
