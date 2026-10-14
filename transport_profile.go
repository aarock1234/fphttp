package http

import (
	"crypto/tls"
	"errors"

	utls "github.com/refraction-networking/utls"

	"github.com/aarock1234/fphttp/v2/internal/catalog"
)

// errProfileExternalHTTP2 reports a Transport whose HTTP/2 support comes from
// golang.org/x/net/http2, which cannot send a profile's HTTP/2 settings.
var errProfileExternalHTTP2 = errors.New("fphttp: Profile cannot be combined with an external HTTP/2 transport")

// transportProfile is the state a Transport derives from its Profile on
// first use. It is written only inside nextProtoOnce, by snapshotProfile and
// by the external HTTP/2 check in onceSetNextProtoDefaults, and is read-only
// afterwards, so readers need no lock.
type transportProfile struct {
	// snapshot is the Transport's private deep copy of Profile, or nil when
	// Profile is nil. Every reader uses it instead of Profile, so changes to
	// Profile after first use have no effect. Its Header and H1HeaderCase
	// have canonical keys.
	snapshot *Profile

	// err is the configuration error that every RoundTrip and NewClientConn
	// returns, or nil.
	err error

	// sessionCache resumes TLS sessions of profile handshakes for this
	// Transport only. It is nil when the profile has no ClientHello or
	// session tickets are disabled.
	sessionCache utls.ClientSessionCache

	// hints remembers the client hints each origin asked for with
	// Accept-CH, for this Transport only. The pointer never changes; the
	// store synchronizes its own contents.
	hints *clientHintStore

	// hintValues holds the client hint values of the profile's release,
	// computed once, or nil when the release sends no client hints or the
	// profile has no identity. It is never modified.
	hintValues *catalog.ClientHints

	// catalogPriorities reports that the catalog's per-destination HTTP/2
	// priorities describe the profile (see usesCatalogPriorities).
	catalogPriorities bool
}

// snapshotProfile copies Profile, validates the copy together with the
// Transport settings it depends on, and creates the TLS session cache and
// the client hint store. It runs at the start of onceSetNextProtoDefaults,
// before any other initialization reads the profile.
//
// The copy's Header gets canonical keys, with a field spelled several ways
// merged as in a request's Header (see normalizeHeader), so requests find
// its fields by canonical key. A nil Header stays nil.
func (t *Transport) snapshotProfile() {
	if t.Profile == nil {
		return
	}

	snapshot := t.Profile.Clone()
	err := t.validateProfile(snapshot)
	snapshot.H1HeaderCase = canonicalHeaderCase(snapshot.H1HeaderCase)
	snapshot.Header, _ = normalizeHeader(snapshot.Header)

	t.profileState = transportProfile{
		snapshot:          snapshot,
		err:               err,
		sessionCache:      newProfileSessionCache(snapshot, t.TLSClientConfig),
		hints:             new(clientHintStore),
		hintValues:        snapshot.clientHintValues(),
		catalogPriorities: usesCatalogPriorities(snapshot),
	}
}

// clientHintValues returns the client hint values of p's release, or nil
// when the release sends no client hints or p has no identity. The caller
// owns the result.
func (p *Profile) clientHintValues() *catalog.ClientHints {
	if !p.hasIdentity() {
		return nil
	}

	return p.entry.ClientHints()
}

// validateProfile checks a profile snapshot and the Transport settings that
// cannot honor it. It returns every problem joined with errors.Join.
func (t *Transport) validateProfile(snapshot *Profile) error {
	return errors.Join(
		snapshot.validate(),
		validateTLSOwnership(snapshot, t.TLSClientConfig),
		t.validateProfileProtocols(),
	)
}

// validateProfileProtocols rejects protocol settings that a profile cannot
// shape: HTTP/3, which brings its own TLS stack, and an HTTP/2
// implementation other than the built-in one.
func (t *Transport) validateProfileProtocols() error {
	var problems []error

	if t.Protocols != nil && t.Protocols.http3() {
		problems = append(problems, errors.New("fphttp: Profile cannot be combined with HTTP/3 in Transport.Protocols"))
	}

	if t.TLSNextProto["h2"] != nil {
		problems = append(problems, errors.New("fphttp: Profile requires the built-in HTTP/2 implementation, but TLSNextProto has an h2 entry"))
	}

	return errors.Join(problems...)
}

// newProfileSessionCache returns the TLS session cache of a Transport whose
// profile owns the ClientHello. It returns nil when the handshake uses
// crypto/tls, which keeps TLSClientConfig's own cache, or when
// TLSClientConfig disables session tickets.
func newProfileSessionCache(snapshot *Profile, config *tls.Config) utls.ClientSessionCache {
	if snapshot.TLS.NewHello == nil {
		return nil
	}

	if config != nil && config.SessionTicketsDisabled {
		return nil
	}

	return utls.NewLRUClientSessionCache(0)
}

// usesProfileTLS reports whether origin TLS handshakes send the profile's
// ClientHello through uTLS.
func (t *Transport) usesProfileTLS() bool {
	snapshot := t.profileState.snapshot

	return snapshot != nil && snapshot.TLS.NewHello != nil
}
