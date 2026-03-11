package http

import (
	utls "github.com/refraction-networking/utls"
)

// H2Setting is an HTTP/2 SETTINGS parameter (ID and value pair).
// The order of settings in a slice is preserved when writing the
// SETTINGS frame during connection initialization.
type H2Setting struct {
	ID  uint16
	Val uint32
}

// Common HTTP/2 setting IDs.
const (
	H2SettingHeaderTableSize       uint16 = 0x1
	H2SettingEnablePush            uint16 = 0x2
	H2SettingMaxConcurrentStreams  uint16 = 0x3
	H2SettingInitialWindowSize     uint16 = 0x4
	H2SettingMaxFrameSize          uint16 = 0x5
	H2SettingMaxHeaderListSize     uint16 = 0x6
	H2SettingEnableConnectProtocol uint16 = 0x8
)

// H2Priority is the priority signal sent with HTTP/2 HEADERS frames.
// A zero value means no priority is included.
type H2Priority struct {
	StreamDep uint32
	Exclusive bool
	Weight    uint8
}

// H2Fingerprint configures HTTP/2 connection-level fingerprint parameters.
type H2Fingerprint struct {
	// Settings are the HTTP/2 SETTINGS frame values sent during
	// connection initialization. The order of entries is preserved
	// on the wire. If nil, standard Go defaults are used.
	Settings []H2Setting

	// ConnectionFlow is the connection-level window size increment
	// sent via WINDOW_UPDATE after the initial SETTINGS frame.
	// Zero means no override; the standard Go default is used.
	ConnectionFlow uint32

	// HeaderPriority is the PRIORITY information included in
	// HEADERS frames. A zero value means no priority is set.
	HeaderPriority H2Priority
}

// Fingerprint configures TLS and HTTP/2 fingerprinting on a Transport.
// A nil Fingerprint on a Transport means standard Go behavior with no
// fingerprint modifications.
type Fingerprint struct {
	// ClientHelloID selects the uTLS ClientHello fingerprint for
	// TLS connections. When set, the Transport uses uTLS instead
	// of crypto/tls for the TLS handshake.
	ClientHelloID utls.ClientHelloID

	// HeaderOrder specifies the order in which HTTP/1.1 headers
	// are written on the wire. Keys should be in canonical form
	// (e.g. "Content-Type", not "content-type"). Headers present
	// in the request but absent from this list are appended in
	// sorted order after the ordered headers.
	//
	// For HTTP/2, headers are lowercased automatically; this
	// controls the iteration order of regular (non-pseudo) headers.
	//
	// A nil value means headers are written in sorted order
	// (the standard Go default).
	HeaderOrder []string

	// PseudoHeaderOrder specifies the order of HTTP/2 pseudo-headers
	// (:method, :authority, :scheme, :path). All four must be present
	// for a non-CONNECT request. If nil, the standard Go order is
	// used (:authority, :method, :path, :scheme).
	PseudoHeaderOrder []string

	// H2 configures HTTP/2 connection parameters for fingerprinting.
	H2 H2Fingerprint
}

// cloneFingerprint returns a deep copy of f. Returns nil if f is nil.
func cloneFingerprint(f *Fingerprint) *Fingerprint {
	if f == nil {
		return nil
	}

	f2 := &Fingerprint{
		ClientHelloID: f.ClientHelloID,
		H2: H2Fingerprint{
			ConnectionFlow: f.H2.ConnectionFlow,
			HeaderPriority: f.H2.HeaderPriority,
		},
	}

	if f.HeaderOrder != nil {
		f2.HeaderOrder = make([]string, len(f.HeaderOrder))
		copy(f2.HeaderOrder, f.HeaderOrder)
	}

	if f.PseudoHeaderOrder != nil {
		f2.PseudoHeaderOrder = make([]string, len(f.PseudoHeaderOrder))
		copy(f2.PseudoHeaderOrder, f.PseudoHeaderOrder)
	}

	if f.H2.Settings != nil {
		f2.H2.Settings = make([]H2Setting, len(f.H2.Settings))
		copy(f2.H2.Settings, f.H2.Settings)
	}

	return f2
}
