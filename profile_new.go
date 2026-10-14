package http

import (
	"errors"
	"maps"
	"slices"

	"github.com/aarock1234/fphttp/v2/internal/catalog"
)

// NewProfile returns the profile of a browser release on a platform. Latest
// selects the newest release fphttp ships.
//
// Accepted version forms:
//   - Chrome and Edge: a major ("152") or any full build of it
//     ("152.0.7977.85"). A major selects its newest cataloged build; a full
//     build is reported verbatim, because builds within a major never differ
//     on the wire.
//   - Brave: a Brave line ("1.90"), a full Brave build ("1.90.128"), or the
//     Chromium major of a Brave line ("148"). The profile reports Brave's
//     own version.
//   - Firefox and Firefox ESR: a major ("150") or a full build ("150.0.3"),
//     both selecting the newest build of that major.
//   - Safari: an exact captured release ("27" or "27.0"). Safari releases
//     are never extrapolated.
//
// The profile's Header holds the release's User-Agent and default
// Accept-Language for an English (United States) locale; every other
// browser field is generated per request. Its orders, casing, ClientHello,
// and HTTP/2 settings are fresh copies that the caller owns and may change.
//
// A version newer than the newest supported release returns the newest
// release's profile together with an error wrapping ErrVersionTooNew. Every
// other failure returns a nil profile and an error wrapping
// ErrUnknownBrowser, ErrUnknownPlatform, ErrUnsupportedPlatform, or
// ErrUnknownVersion.
func NewProfile(browser Browser, platform Platform, version Version) (*Profile, error) {
	entry, err := catalog.Lookup(catalog.Browser(browser), catalog.Platform(platform), string(version))
	if err != nil && !errors.Is(err, ErrVersionTooNew) {
		return nil, err
	}

	return newCatalogProfile(entry), err
}

// newCatalogProfile builds the profile of a catalog release. Every slice and
// map is freshly allocated, because the catalog's wire values are shared by
// all releases in a span and must never be modified.
func newCatalogProfile(entry catalog.Entry) *Profile {
	wire := entry.Wire

	return &Profile{
		Header:                 identityHeader(entry),
		HeaderOrder:            slices.Clone(wire.NavigationOrder),
		SubresourceHeaderOrder: slices.Clone(wire.SubresourceOrder),
		PseudoHeaderOrder:      slices.Clone(wire.PseudoHeaderOrder),
		H1HeaderCase:           maps.Clone(wire.H1HeaderCase),
		TLS: TLSProfile{
			NewHello: wire.NewHello,
		},
		HTTP2: wire.HTTP2.Clone(),
		entry: &entry,
	}
}

// identityHeader returns the fields a release sends with every request:
// exactly its User-Agent and default Accept-Language, under canonical keys.
func identityHeader(entry catalog.Entry) Header {
	return Header{
		"User-Agent":      {entry.UserAgent()},
		"Accept-Language": {entry.AcceptLanguage()},
	}
}
