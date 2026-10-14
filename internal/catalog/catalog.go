// Package catalog holds fphttp's browser knowledge as Go source: which
// browser releases are supported on which platforms, and the wire
// configuration (ClientHello, HTTP/2 preface, header layout) each release
// shares with its neighbors.
//
// The release table in builds_gen.go is generated from official release
// feeds. Everything else is written by hand from browser source and real
// captures.
//
// Entry methods return the values a release sends per request:
// User-Agent, Accept-Language, Accept, Accept-Encoding, Range,
// Upgrade-Insecure-Requests, Sec-Fetch-User, request priority, client
// hints, and HTTP/2-only fields. Where neither source nor a capture
// establishes a value, a method keeps fphttp v1's behavior and its comment
// says so. The few deliberate departures from v1 without such evidence are
// documented where they occur.
//
// Entry and Wire values returned by this package are shared by every caller
// and must be treated as immutable. A caller that wants to change a slice,
// map, or HTTP/2 template must deep-copy it first.
//
//go:generate go run ../cmd/syncprofiles -out builds_gen.go
package catalog

import "errors"

// Browser identifies a browser product.
type Browser string

// Supported browser products. Firefox ESR is its own product because its
// releases follow a separate track with a different wire.
const (
	// Chrome is Google Chrome.
	Chrome Browser = "chrome"

	// Edge is Microsoft Edge.
	Edge Browser = "edge"

	// Brave is the Brave browser, versioned by its own release line.
	Brave Browser = "brave"

	// Firefox is Mozilla Firefox on the stable release track.
	Firefox Browser = "firefox"

	// FirefoxESR is Mozilla Firefox on the Extended Support Release track.
	FirefoxESR Browser = "firefox-esr"

	// Safari is Apple Safari.
	Safari Browser = "safari"
)

// Platform identifies the operating system a browser runs on.
type Platform string

// Recognized platforms. Recognizing a platform does not mean every browser
// has a profile for it.
const (
	// Windows is 64-bit Windows 10 or 11.
	Windows Platform = "windows"

	// Mac is macOS.
	Mac Platform = "mac"

	// Linux is 64-bit x86 desktop Linux.
	Linux Platform = "linux"

	// Android is an Android phone.
	Android Platform = "android"

	// IOS is an iPhone.
	IOS Platform = "ios"

	// IPadOS is an iPad. No browser has a profile for it.
	IPadOS Platform = "ipados"
)

// Family identifies the browser engine whose network stack a release uses.
// The zero value is not a family.
type Family uint8

// Browser engine families.
const (
	// FamilyChromium covers Chrome, Edge, and Brave.
	FamilyChromium Family = iota + 1

	// FamilyFirefox covers Firefox and Firefox ESR.
	FamilyFirefox

	// FamilySafari covers Safari.
	FamilySafari
)

// build is one generated row of builds_gen.go: the newest published build
// of one browser major version on one platform.
type build struct {
	browser  Browser
	platform Platform
	version  string
	engine   string
	released string
}

// Entry is one supported release of a browser on one platform. Only stable
// channels are cataloged; Firefox ESR is its own Browser.
type Entry struct {
	// Browser is the browser product.
	Browser Browser

	// Platform is the operating system the release runs on.
	Platform Platform

	// Version is the product build, such as "152.0.7977.85", Brave
	// "1.90.128", or Safari "27.0".
	Version string

	// Engine is the Chromium build for Chrome and Brave and the Gecko
	// version for Firefox. It is empty for Safari, and for Edge, whose
	// Chromium build has no official source; Edge's Chromium major equals
	// its own major.
	Engine string

	// Released is the release date as YYYY-MM-DD. It is empty for a Chrome
	// or Edge build that Lookup reported verbatim and the catalog does not
	// list.
	Released string

	// Family is the engine family of Browser.
	Family Family

	// Wire is the wire configuration of the release. It is shared with
	// every other release in the same span and must not be modified.
	Wire *Wire
}

var (
	// ErrUnknownBrowser reports a Browser that fphttp does not recognize.
	ErrUnknownBrowser = errors.New("fphttp: unknown browser")

	// ErrUnknownPlatform reports a Platform that fphttp does not recognize.
	ErrUnknownPlatform = errors.New("fphttp: unknown platform")

	// ErrUnsupportedPlatform reports a browser that has no profile on a
	// platform, such as Safari on Windows.
	ErrUnsupportedPlatform = errors.New("fphttp: browser has no profile for platform")

	// ErrUnknownVersion reports a version that is malformed, older than the
	// oldest supported release, or otherwise not cataloged, such as a
	// dropped release or a Safari release with no captured wire.
	ErrUnknownVersion = errors.New("fphttp: unknown browser version")

	// ErrVersionTooNew reports a version newer than the newest supported
	// release. Lookup returns the newest entry together with this error.
	ErrVersionTooNew = errors.New("fphttp: browser version is newer than the newest supported release")
)
