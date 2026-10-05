package http

import (
	"crypto/tls"
	"errors"
	"slices"

	utls "github.com/refraction-networking/utls"

	"github.com/aarock1234/fphttp/internal/fingerprint"
)

// H2SettingID identifies an HTTP/2 SETTINGS parameter.
type H2SettingID = fingerprint.SettingID

// Common HTTP/2 setting IDs.
const (
	H2SettingHeaderTableSize       = fingerprint.SettingHeaderTableSize
	H2SettingEnablePush            = fingerprint.SettingEnablePush
	H2SettingMaxConcurrentStreams  = fingerprint.SettingMaxConcurrentStreams
	H2SettingInitialWindowSize     = fingerprint.SettingInitialWindowSize
	H2SettingMaxFrameSize          = fingerprint.SettingMaxFrameSize
	H2SettingMaxHeaderListSize     = fingerprint.SettingMaxHeaderListSize
	H2SettingEnableConnectProtocol = fingerprint.SettingEnableConnectProtocol
	H2SettingNoRFC7540Priorities   = fingerprint.SettingNoRFC7540Priorities
)

// H2Setting is an ordered HTTP/2 SETTINGS parameter.
type H2Setting = fingerprint.Setting

// H2Priority is the optional priority signal in a HEADERS frame.
// Weight is the wire value, from 0 to 255, representing weights 1 to 256.
type H2Priority = fingerprint.Priority

// H2PriorityFrame is a standalone PRIORITY frame sent during initialization.
type H2PriorityFrame = fingerprint.PriorityFrame

// H2Fingerprint configures the initial HTTP/2 connection frames.
type H2Fingerprint = fingerprint.HTTP2

// Fingerprint configures TLS, HTTP/2, and request header ordering.
// A nil fingerprint uses Go's TLS and HTTP defaults.
// A fingerprint must not be modified after the transport starts using it.
type Fingerprint struct {
	// ClientHelloID selects a uTLS preset. Its zero value uses crypto/tls.
	ClientHelloID utls.ClientHelloID

	// ClientHelloSpec provides a custom template. Supported extensions are
	// copied for every connection, including their mutable slices.
	// Stateful or third-party extensions require ClientHelloSpecFactory.
	// A custom spec automatically selects utls.HelloCustom.
	ClientHelloSpec *utls.ClientHelloSpec

	// ClientHelloSpecFactory constructs a fresh custom spec for each handshake.
	// It may be called concurrently and must return independently owned
	// extensions and slices. It cannot be combined with ClientHelloSpec or
	// a named ClientHelloID preset.
	ClientHelloSpecFactory func() (*utls.ClientHelloSpec, error)

	// ClientSessionCache enables uTLS session resumption. The cache must be
	// safe for concurrent use; utls.NewLRUClientSessionCache is suitable.
	// A nil cache disables resumption.
	ClientSessionCache utls.ClientSessionCache

	// GetClientCertificate selects a client certificate using uTLS's request
	// type, which preserves the handshake context. It may be called concurrently.
	// Static Certificates in Transport.TLSClientConfig remain supported.
	GetClientCertificate func(*utls.CertificateRequestInfo) (*utls.Certificate, error)

	// HeaderOrder specifies canonical HTTP header names in wire order.
	// Remaining headers follow in sorted order. An explicitly empty request
	// order disables the fingerprint's order for that request.
	HeaderOrder []string

	// PseudoHeaderOrder specifies all four HTTP/2 request pseudo-headers.
	// A nil or empty order uses Go's order: authority, method, path, scheme.
	PseudoHeaderOrder []string

	// H2 configures HTTP/2 connection fingerprinting.
	H2 H2Fingerprint
}

// Clone copies the fingerprint's slices. The custom spec template, factory,
// and session cache are shared and must be immutable or concurrency-safe.
// The template is separately copied before each handshake.
func (f *Fingerprint) Clone() *Fingerprint {
	if f == nil {
		return nil
	}

	clone := *f
	clone.HeaderOrder = slices.Clone(f.HeaderOrder)
	clone.PseudoHeaderOrder = slices.Clone(f.PseudoHeaderOrder)
	clone.H2.Settings = slices.Clone(f.H2.Settings)
	clone.H2.InitPriorityFrames = slices.Clone(f.H2.InitPriorityFrames)

	return &clone
}

// Validate returns all configuration problems joined with errors.Join.
// Transports also validate their fingerprint before sending requests.
func (f *Fingerprint) Validate() error {
	if f == nil {
		return nil
	}

	return errors.Join(
		f.validateClientHello(),
		fingerprint.ValidateHeaderOrder(f.HeaderOrder),
		fingerprint.ValidatePseudoHeaderOrder(f.PseudoHeaderOrder),
		f.H2.Validate(),
	)
}

func (f *Fingerprint) validateClientHello() error {
	custom := f.ClientHelloSpec != nil || f.ClientHelloSpecFactory != nil
	namedPreset := f.ClientHelloID.IsSet() && f.ClientHelloID != utls.HelloCustom
	if custom && namedPreset {
		return errors.New("fphttp: a custom ClientHello cannot be combined with a named preset")
	}
	if f.ClientHelloSpec != nil && f.ClientHelloSpecFactory != nil {
		return errors.New("fphttp: use either ClientHelloSpec or ClientHelloSpecFactory")
	}
	if f.ClientHelloSpec != nil {
		_, err := cloneClientHelloSpec(f.ClientHelloSpec)

		return err
	}
	if f.ClientHelloID == utls.HelloCustom && f.ClientHelloSpecFactory == nil {
		return errors.New("fphttp: HelloCustom requires ClientHelloSpec or ClientHelloSpecFactory")
	}

	return nil
}

func (f *Fingerprint) hasTLSFingerprint() bool {
	return f != nil && (f.ClientHelloID.IsSet() || f.ClientHelloSpec != nil || f.ClientHelloSpecFactory != nil)
}

func resolveOrder(request, fallback []string) []string {
	return fingerprint.ResolveOrder(request, fallback)
}

func validateRequestOrder(request *Request) error {
	var priorityError error
	if request.H2Priority != nil {
		priorityError = request.H2Priority.Validate(0)
	}

	return errors.Join(
		priorityError,
		fingerprint.ValidateHeaderOrder(request.HeaderOrder),
		fingerprint.ValidatePseudoHeaderOrder(request.PseudoHeaderOrder),
	)
}

func (f *Fingerprint) validateTLSConfig(config *tls.Config) error {
	if !f.hasTLSFingerprint() || config == nil {
		return nil
	}

	var problems []error
	if config.ClientSessionCache != nil && f.ClientSessionCache == nil {
		problems = append(problems, errors.New("fphttp: use Fingerprint.ClientSessionCache for uTLS session resumption"))
	}
	if config.GetClientCertificate != nil && f.GetClientCertificate == nil {
		problems = append(problems, errors.New("fphttp: use Fingerprint.GetClientCertificate to preserve the uTLS handshake context"))
	}

	return errors.Join(problems...)
}
