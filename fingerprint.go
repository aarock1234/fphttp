package http

import (
	"fmt"
	"slices"
	"sort"

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
// A zero value means no priority is included.
type H2Priority struct {
	StreamDep uint32
	Exclusive bool
	Weight    uint8
}

// H2PriorityFrame is a standalone PRIORITY frame sent during HTTP/2
// connection initialization. Browsers like Chrome send these for
// placeholder streams (e.g. 3, 5, 7, 9, 11) to establish a
// dependency tree. This is part of the Akamai HTTP/2 fingerprint.
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
	// frames. Browsers like Chrome use these to establish a dependency
	// tree for placeholder streams. The frames are written in order.
	// If nil, no PRIORITY frames are sent during initialization.
	InitPriorityFrames []H2PriorityFrame

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

// Clone returns a deep copy of f. Returns nil if f is nil.
func (f *Fingerprint) Clone() *Fingerprint {
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

	if f.H2.InitPriorityFrames != nil {
		f2.H2.InitPriorityFrames = make([]H2PriorityFrame, len(f.H2.InitPriorityFrames))
		copy(f2.H2.InitPriorityFrames, f.H2.InitPriorityFrames)
	}

	return f2
}

// requiredPseudoHeaders are the four pseudo-headers that must be present
// in every non-CONNECT HTTP/2 request.
var requiredPseudoHeaders = []string{":method", ":authority", ":scheme", ":path"}

// Validate checks f for common misconfigurations and returns an error
// describing the first problem found. A nil Fingerprint is always valid.
func (f *Fingerprint) Validate() error {
	if f == nil {
		return nil
	}

	if err := f.validatePseudoHeaderOrder(); err != nil {
		return err
	}

	if err := f.validateSettings(); err != nil {
		return err
	}

	if err := f.validateInitPriorityFrames(); err != nil {
		return err
	}

	if err := f.validateHeaderOrder(); err != nil {
		return err
	}

	return nil
}

// validatePseudoHeaderOrder checks that PseudoHeaderOrder, if set,
// contains exactly the four required pseudo-headers with no duplicates.
func (f *Fingerprint) validatePseudoHeaderOrder() error {
	if f.PseudoHeaderOrder == nil {
		return nil
	}

	if len(f.PseudoHeaderOrder) != len(requiredPseudoHeaders) {
		return fmt.Errorf("fphttp: PseudoHeaderOrder has %d entries, want %d",
			len(f.PseudoHeaderOrder), len(requiredPseudoHeaders))
	}

	sorted := make([]string, len(f.PseudoHeaderOrder))
	copy(sorted, f.PseudoHeaderOrder)
	sort.Strings(sorted)

	required := make([]string, len(requiredPseudoHeaders))
	copy(required, requiredPseudoHeaders)
	sort.Strings(required)

	if !slices.Equal(sorted, required) {
		return fmt.Errorf("fphttp: PseudoHeaderOrder must contain exactly %v", requiredPseudoHeaders)
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
