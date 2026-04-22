package http

import (
	"errors"
	"fmt"
	"slices"

	utls "github.com/refraction-networking/utls"
)

// H2SettingID identifies an HTTP/2 SETTINGS parameter.
type H2SettingID uint16

// Common HTTP/2 setting IDs.
const (
	H2SettingHeaderTableSize       H2SettingID = 0x1
	H2SettingEnablePush            H2SettingID = 0x2
	H2SettingMaxConcurrentStreams  H2SettingID = 0x3
	H2SettingInitialWindowSize     H2SettingID = 0x4
	H2SettingMaxFrameSize          H2SettingID = 0x5
	H2SettingMaxHeaderListSize     H2SettingID = 0x6
	H2SettingEnableConnectProtocol H2SettingID = 0x8
)

// String returns the human-readable name of the setting ID.
func (id H2SettingID) String() string {
	switch id {
	case H2SettingHeaderTableSize:
		return "HEADER_TABLE_SIZE"
	case H2SettingEnablePush:
		return "ENABLE_PUSH"
	case H2SettingMaxConcurrentStreams:
		return "MAX_CONCURRENT_STREAMS"
	case H2SettingInitialWindowSize:
		return "INITIAL_WINDOW_SIZE"
	case H2SettingMaxFrameSize:
		return "MAX_FRAME_SIZE"
	case H2SettingMaxHeaderListSize:
		return "MAX_HEADER_LIST_SIZE"
	case H2SettingEnableConnectProtocol:
		return "ENABLE_CONNECT_PROTOCOL"
	default:
		return fmt.Sprintf("UNKNOWN(0x%x)", uint16(id))
	}
}

// H2Setting is an HTTP/2 SETTINGS parameter (ID and value pair).
// The order of settings in a slice is preserved when writing the
// SETTINGS frame during connection initialization.
type H2Setting struct {
	ID  H2SettingID
	Val uint32
}

// H2Priority is the priority signal sent with HTTP/2 HEADERS frames.
// Priority is only emitted when Enabled is true; the zero value emits
// no priority, matching stdlib behavior.
type H2Priority struct {
	Enabled   bool
	StreamDep uint32
	Exclusive bool
	Weight    uint8
}

// H2PriorityFrame is a standalone PRIORITY frame sent during HTTP/2
// connection initialization. Browsers like Firefox send these for
// placeholder streams to establish a dependency tree. This is part
// of the Akamai HTTP/2 fingerprint.
type H2PriorityFrame struct {
	StreamID  uint32
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

	// InitPriorityFrames are standalone PRIORITY frames sent during
	// connection initialization, after the SETTINGS and WINDOW_UPDATE
	// frames. Browsers like Firefox use these to establish a dependency
	// tree for placeholder streams. The frames are written in order.
	// If nil, no PRIORITY frames are sent during initialization.
	InitPriorityFrames []H2PriorityFrame

	// HeaderPriority is the PRIORITY information included in
	// HEADERS frames. The zero value emits no priority; set
	// HeaderPriority.Enabled to true to include it.
	HeaderPriority H2Priority
}

// Fingerprint configures TLS and HTTP/2 fingerprinting on a Transport.
// A nil Fingerprint on a Transport means standard Go behavior with no
// fingerprint modifications.
//
// Fingerprint must not be modified after assignment to a Transport.
// Use Clone to obtain a safely mutable copy.
type Fingerprint struct {
	// ClientHelloID selects the uTLS ClientHello fingerprint for
	// TLS connections. When set, the Transport uses uTLS instead
	// of crypto/tls for the TLS handshake.
	//
	// When ClientHelloSpec is also set, ClientHelloSpec takes
	// precedence and ClientHelloID is ignored except that it is
	// still passed to uTLS as a label.
	ClientHelloID utls.ClientHelloID

	// ClientHelloSpec, when non-nil, provides a fully customized
	// ClientHello message that overrides ClientHelloID. Use this
	// to mimic browser versions uTLS does not ship with a preset
	// for, or to match JA3/JA4 strings exactly.
	//
	// When ClientHelloSpec is set, ClientHelloID should be set to
	// utls.HelloCustom so uTLS marks the handshake as custom.
	ClientHelloSpec *utls.ClientHelloSpec

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

// Clone returns a deep copy of f or nil if f is nil. The embedded
// ClientHelloSpec pointer is shared, not deep-copied; callers must
// not mutate a spec in place after cloning.
func (f *Fingerprint) Clone() *Fingerprint {
	if f == nil {
		return nil
	}

	f2 := *f
	f2.HeaderOrder = slices.Clone(f.HeaderOrder)
	f2.PseudoHeaderOrder = slices.Clone(f.PseudoHeaderOrder)
	f2.H2.Settings = slices.Clone(f.H2.Settings)
	f2.H2.InitPriorityFrames = slices.Clone(f.H2.InitPriorityFrames)

	return &f2
}

// Validate checks f for common misconfigurations. It returns all
// problems found joined via errors.Join, or nil if f is valid.
// A nil Fingerprint is always valid.
func (f *Fingerprint) Validate() error {
	if f == nil {
		return nil
	}

	return errors.Join(
		f.validatePseudoHeaderOrder(),
		f.validateSettings(),
		f.validateInitPriorityFrames(),
		f.validateHeaderOrder(),
	)
}

// validatePseudoHeaderOrder checks that PseudoHeaderOrder, if set,
// contains exactly the four required pseudo-headers with no duplicates.
func (f *Fingerprint) validatePseudoHeaderOrder() error {
	if f.PseudoHeaderOrder == nil {
		return nil
	}

	required := map[string]bool{
		":method":    true,
		":authority": true,
		":scheme":    true,
		":path":      true,
	}
	seen := make(map[string]bool, len(required))
	for _, p := range f.PseudoHeaderOrder {
		if !required[p] {
			return fmt.Errorf("fphttp: PseudoHeaderOrder contains invalid pseudo-header %q", p)
		}
		if seen[p] {
			return fmt.Errorf("fphttp: PseudoHeaderOrder contains duplicate %q", p)
		}
		seen[p] = true
	}

	for p := range required {
		if !seen[p] {
			return fmt.Errorf("fphttp: PseudoHeaderOrder missing required pseudo-header %q", p)
		}
	}

	return nil
}

// validateSettings checks that H2.Settings has no duplicate setting IDs.
func (f *Fingerprint) validateSettings() error {
	if len(f.H2.Settings) == 0 {
		return nil
	}

	seen := make(map[H2SettingID]bool, len(f.H2.Settings))
	for _, s := range f.H2.Settings {
		if seen[s.ID] {
			return fmt.Errorf("fphttp: duplicate H2 setting ID %v", s.ID)
		}
		seen[s.ID] = true
	}

	return nil
}

// validateInitPriorityFrames checks that InitPriorityFrames entries
// have non-zero stream IDs (stream 0 is the connection, not a valid
// PRIORITY target).
func (f *Fingerprint) validateInitPriorityFrames() error {
	for i, pf := range f.H2.InitPriorityFrames {
		if pf.StreamID == 0 {
			return fmt.Errorf("fphttp: InitPriorityFrames[%d] has StreamID 0", i)
		}
	}

	return nil
}

// validateHeaderOrder checks that HeaderOrder keys are in canonical
// HTTP/1.1 form (e.g. "Content-Type", not "content-type").
func (f *Fingerprint) validateHeaderOrder() error {
	for _, key := range f.HeaderOrder {
		if canonical := CanonicalHeaderKey(key); canonical != key {
			return fmt.Errorf("fphttp: HeaderOrder key %q is not canonical, use %q", key, canonical)
		}
	}

	return nil
}

// resolveOrder returns perReq if non-nil, else fallback. It is the
// per-request-overrides-fingerprint-default pattern used by the H1
// and H2 write paths.
func resolveOrder(perReq, fallback []string) []string {
	if perReq != nil {
		return perReq
	}

	return fallback
}
