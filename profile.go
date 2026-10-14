package http

import (
	"maps"
	"slices"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/aarock1234/fphttp/v2/internal/catalog"
	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// Profile describes how a browser release looks on the wire and in its
// headers. NewProfile returns a complete profile whose exported fields can be
// read and changed. A Transport copies its Profile on first use, so later
// changes to the profile do not affect that transport.
//
// A Profile that NewProfile did not create, such as a composite literal, has
// no release identity: a Transport sends its TLS, HTTP/2, order, casing, and
// Header settings but generates no browser fields, and String returns
// "custom profile".
//
// A Profile may be read from several goroutines at once, but changing it
// while another goroutine reads it, including a Transport taking its first
// copy, is a data race.
type Profile struct {
	// Header holds fields sent with every request, such as User-Agent and
	// Accept-Language. fphttp generates the remaining browser fields per
	// request (Accept, Sec-Fetch-*, client hints, Accept-Encoding, Priority)
	// unless Header or the request already contains them. A present but empty
	// value suppresses a field. A nil Header disables every generated field
	// and sends only the caller's headers.
	Header Header

	// HeaderOrder orders fields for top-level page loads and iframes. Names
	// match fields ignoring case, and fields it does not list follow in
	// sorted order. An empty non-nil HeaderOrder selects Go's order.
	HeaderOrder []string

	// SubresourceHeaderOrder orders fields for fetch, XHR, and subresource
	// requests. A nil SubresourceHeaderOrder uses HeaderOrder.
	SubresourceHeaderOrder []string

	// PseudoHeaderOrder orders the four HTTP/2 request pseudo-header fields.
	// An empty PseudoHeaderOrder selects Go's order.
	PseudoHeaderOrder []string

	// H1HeaderCase maps field names to their HTTP/1.1 spelling. Keys match
	// fields ignoring case, and each value must spell its key with different
	// case only. A request's own H1HeaderCase wins per field. HTTP/2 always
	// sends lowercase names.
	H1HeaderCase map[string]string

	// TLS describes the ClientHello.
	TLS TLSProfile

	// HTTP2 describes the HTTP/2 connection preface and request priorities.
	HTTP2 HTTP2Profile

	// entry is the catalog release NewProfile resolved, or nil for a profile
	// without identity. It holds the browser, platform, version, engine
	// version, and per-destination values. It is never modified after
	// NewProfile returns, so clones share it.
	entry *catalog.Entry
}

// TLSProfile describes the ClientHello. Verification, server name,
// certificates, and key logging belong to Transport.TLSClientConfig.
//
// When NewHello is set, the Transport performs every origin TLS handshake
// with uTLS and the profile owns the ClientHello. TLSClientConfig must then
// leave MinVersion, MaxVersion, CipherSuites, CurvePreferences, and
// ClientSessionCache unset, because each would change or bypass the
// ClientHello; otherwise the first request fails with an error naming the
// conflicting fields. The remaining TLSClientConfig fields apply as they do
// for crypto/tls: ServerName, InsecureSkipVerify, RootCAs, Certificates,
// GetClientCertificate, VerifyPeerCertificate, VerifyConnection,
// KeyLogWriter, Rand, Time, Renegotiation, SessionTicketsDisabled, and the
// Encrypted Client Hello config list. The CertificateRequestInfo passed to
// GetClientCertificate has no handshake context, so its Context method
// returns nil.
//
// Each Transport resumes TLS sessions through a cache of its own, which
// TLSClientConfig.SessionTicketsDisabled turns off. Connections configured
// for Encrypted Client Hello never resume, because uTLS cannot carry a
// resumed session in the encrypted inner ClientHello.
//
// The ClientHello does not apply to the TLS connection with an HTTPS proxy,
// which uses crypto/tls with TLSClientConfig, nor to connections dialed by
// Transport.DialTLS or DialTLSContext, which own TLS entirely. The profile's
// HTTP/2 and header settings still apply on those connections.
type TLSProfile struct {
	// NewHello returns a fresh ClientHello for each connection. It must be
	// safe for concurrent use, and each call must return a spec whose
	// extensions and slices the caller owns.
	//
	// The Transport fills the session ticket and pre_shared_key extensions
	// from its session cache, so the spec must leave them uninitialized,
	// and pre_shared_key must be a *utls.UtlsPreSharedKeyExtension placed
	// last. A spec parsed from a captured ClientHello has that type only
	// when the parser's real PSK option is set, such as
	// utls.Fingerprinter.RealPSKResumption or
	// utls.TLSExtensionsJSONUnmarshaler.UseRealPSK.
	//
	// A spec with a nil extension, more than one session ticket extension,
	// a session extension that already holds a session, or any other
	// pre_shared_key extension fails the connection with an error.
	//
	// A nil NewHello uses crypto/tls with TLSClientConfig, as a Transport
	// without a Profile does.
	NewHello func() (*utls.ClientHelloSpec, error)
}

// HTTP2Profile describes the HTTP/2 connection preface and the default
// request priority: the SETTINGS in wire order (Settings), the connection
// WINDOW_UPDATE increment (ConnectionFlow), the first stream ID
// (InitialStreamID), the PRIORITY frames sent after the preface
// (InitPriorityFrames), and the HEADERS priority of a top-level page load
// (HeaderPriority).
//
// These values take precedence over Transport.HTTP2 where both describe the
// same setting. A MAX_HEADER_LIST_SIZE setting also lowers the response
// header limit below Transport.MaxResponseHeaderBytes.
type HTTP2Profile = fingerprint.HTTP2

// Browser returns the browser product of the release that NewProfile
// resolved, or the empty Browser for a profile without identity. Identity is
// read-only because changing it would not change what is sent.
func (p *Profile) Browser() Browser {
	if !p.hasIdentity() {
		return ""
	}

	return Browser(p.entry.Browser)
}

// Platform returns the platform of the release that NewProfile resolved, or
// the empty Platform for a profile without identity.
func (p *Profile) Platform() Platform {
	if !p.hasIdentity() {
		return ""
	}

	return Platform(p.entry.Platform)
}

// Version returns the full build of the release that NewProfile resolved,
// such as "152.0.7977.85", "1.90.128" for Brave, or "27.0" for Safari. It
// is empty for a profile without identity.
func (p *Profile) Version() Version {
	if !p.hasIdentity() {
		return ""
	}

	return Version(p.entry.Version)
}

// String describes the release, such as "Chrome 152.0.7977.85 on Windows" or
// "Brave 1.90.128 (Chromium 148) on Linux". A profile without identity is
// "custom profile".
func (p *Profile) String() string {
	switch {
	case p == nil:
		return "<nil>"

	case p.entry == nil:
		return "custom profile"
	}

	release := p.Browser().displayName() + " " + p.entry.Version
	if engine := p.engineLabel(); engine != "" {
		release += " (" + engine + ")"
	}

	return release + " on " + p.Platform().displayName()
}

// Clone returns a deep copy of p that shares no mutable state with it.
// Header, HeaderOrder, SubresourceHeaderOrder, PseudoHeaderOrder,
// H1HeaderCase, and the HTTP2 Settings and InitPriorityFrames slices are
// copied, and each keeps its nilness: a nil Header stays nil and an empty
// non-nil order stays empty. TLS.NewHello and the release identity are
// shared, because NewHello must be safe for concurrent use and the identity
// never changes. Clone of a nil Profile returns nil.
func (p *Profile) Clone() *Profile {
	if p == nil {
		return nil
	}

	clone := *p
	clone.Header = p.Header.Clone()
	clone.HeaderOrder = slices.Clone(p.HeaderOrder)
	clone.SubresourceHeaderOrder = slices.Clone(p.SubresourceHeaderOrder)
	clone.PseudoHeaderOrder = slices.Clone(p.PseudoHeaderOrder)
	clone.H1HeaderCase = maps.Clone(p.H1HeaderCase)
	clone.HTTP2 = p.HTTP2.Clone()

	return &clone
}

// hasIdentity reports whether p came from NewProfile and so knows which
// browser release it describes.
func (p *Profile) hasIdentity() bool {
	return p != nil && p.entry != nil
}

// family returns the engine family of p's release, or zero for a profile
// without identity.
func (p *Profile) family() catalog.Family {
	if !p.hasIdentity() {
		return 0
	}

	return p.entry.Family
}

// engineLabel names the Chromium major of a Brave release, such as
// "Chromium 148", because Brave's own version does not reveal it. It is
// empty for every other browser and when the Chromium build is unknown.
func (p *Profile) engineLabel() string {
	if p.entry.Browser != catalog.Brave {
		return ""
	}

	major, _, _ := strings.Cut(p.entry.Engine, ".")
	if major == "" {
		return ""
	}

	return "Chromium " + major
}
