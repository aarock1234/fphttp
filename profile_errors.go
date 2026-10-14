package http

import "github.com/aarock1234/fphttp/v2/internal/catalog"

// Errors returned by NewProfile. Each wraps more context, such as the
// rejected value, so compare them with errors.Is. They are the same values
// the internal browser catalog returns, so errors.Is matches either.
var (
	// ErrUnknownBrowser reports a Browser that fphttp does not recognize.
	ErrUnknownBrowser = catalog.ErrUnknownBrowser

	// ErrUnknownPlatform reports a Platform that fphttp does not recognize.
	ErrUnknownPlatform = catalog.ErrUnknownPlatform

	// ErrUnsupportedPlatform reports a browser that has no profile on a
	// platform, such as Safari on Windows.
	ErrUnsupportedPlatform = catalog.ErrUnsupportedPlatform

	// ErrUnknownVersion reports a version that is malformed, older than the
	// oldest supported release, or otherwise not cataloged, such as a
	// dropped release.
	ErrUnknownVersion = catalog.ErrUnknownVersion

	// ErrVersionTooNew reports a version newer than the newest supported
	// release. It is the one error that comes with a usable profile:
	// NewProfile returns the newest release's profile together with an error
	// wrapping ErrVersionTooNew, as strconv.ParseInt returns the clamped
	// value with ErrRange. Callers that accept the newest release instead
	// can keep the profile and ignore this error.
	ErrVersionTooNew = catalog.ErrVersionTooNew
)
