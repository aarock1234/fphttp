// Package fingerprint defines the wire configuration that the root package,
// the HTTP/2 transport, and the browser catalog share: the HTTP/2
// connection preface and request priority, and the validation rules for
// header order and HTTP/1.1 field casing.
package fingerprint

import (
	"fmt"
	"slices"
)

// SettingID identifies an HTTP/2 SETTINGS parameter.
type SettingID uint16

// Common HTTP/2 SETTINGS parameters.
const (
	SettingHeaderTableSize       SettingID = 0x1
	SettingEnablePush            SettingID = 0x2
	SettingMaxConcurrentStreams  SettingID = 0x3
	SettingInitialWindowSize     SettingID = 0x4
	SettingMaxFrameSize          SettingID = 0x5
	SettingMaxHeaderListSize     SettingID = 0x6
	SettingEnableConnectProtocol SettingID = 0x8
	SettingNoRFC7540Priorities   SettingID = 0x9
)

// String returns the setting's protocol name.
func (id SettingID) String() string {
	switch id {
	case SettingHeaderTableSize:
		return "HEADER_TABLE_SIZE"
	case SettingEnablePush:
		return "ENABLE_PUSH"
	case SettingMaxConcurrentStreams:
		return "MAX_CONCURRENT_STREAMS"
	case SettingInitialWindowSize:
		return "INITIAL_WINDOW_SIZE"
	case SettingMaxFrameSize:
		return "MAX_FRAME_SIZE"
	case SettingMaxHeaderListSize:
		return "MAX_HEADER_LIST_SIZE"
	case SettingEnableConnectProtocol:
		return "ENABLE_CONNECT_PROTOCOL"
	case SettingNoRFC7540Priorities:
		return "NO_RFC7540_PRIORITIES"
	default:
		return fmt.Sprintf("UNKNOWN(0x%x)", uint16(id))
	}
}

// Setting is an ordered HTTP/2 setting.
type Setting struct {
	// ID identifies the parameter carried in this setting.
	ID SettingID

	// Val is the parameter's wire value, in the units defined by ID.
	Val uint32
}

// Priority is the optional priority signal in a HEADERS frame.
// Weight is the wire value, one less than the effective weight.
type Priority struct {
	// Enabled includes the priority signal, even when every wire field is zero.
	Enabled bool

	// StreamDep is the 31-bit dependency stream ID; zero selects the root.
	StreamDep uint32

	// Exclusive makes this stream the dependency's sole child.
	Exclusive bool

	// Weight is the wire value, from 0 to 255, representing weights 1 to 256.
	Weight uint8
}

// PriorityFrame is a standalone PRIORITY frame.
type PriorityFrame struct {
	// StreamID is the non-zero 31-bit stream ID being prioritized.
	StreamID uint32

	// StreamDep is the 31-bit dependency stream ID; zero selects the root.
	StreamDep uint32

	// Exclusive makes this stream the dependency's sole child.
	Exclusive bool

	// Weight is the wire value, from 0 to 255, representing weights 1 to 256.
	Weight uint8
}

// HTTP2 configures the initial HTTP/2 connection frames and the default
// priority of request HEADERS frames.
type HTTP2 struct {
	// Settings replaces the initial SETTINGS frame when non-nil, in wire
	// order. It must explicitly disable server push, which this client does
	// not support. A nil Settings sends Go's SETTINGS.
	Settings []Setting

	// ConnectionFlow overrides the initial WINDOW_UPDATE increment.
	// Zero uses the standard Go increment.
	ConnectionFlow uint32

	// InitialStreamID selects the first client stream. Zero uses stream 1.
	InitialStreamID uint32

	// InitPriorityFrames are sent after SETTINGS and WINDOW_UPDATE.
	InitPriorityFrames []PriorityFrame

	// HeaderPriority controls priority information in request HEADERS frames.
	HeaderPriority Priority
}

// Config is the profile configuration the HTTP/2 transport reads. The
// transport shares one Config between all of its connections, so a Config
// must not be modified once a transport uses it.
type Config struct {
	// HeaderOrder lists regular header names in wire order. Names match
	// fields ignoring case.
	HeaderOrder []string

	// PseudoHeaderOrder lists all four request pseudo-headers in wire order.
	PseudoHeaderOrder []string

	// H2 configures the connection frames and default request priority.
	H2 HTTP2
}

// SettingValue returns the first setting with the given ID.
func (h HTTP2) SettingValue(id SettingID) (uint32, bool) {
	for _, setting := range h.Settings {
		if setting.ID == id {
			return setting.Val, true
		}
	}

	return 0, false
}

// Clone returns a deep copy of h. The Settings and InitPriorityFrames slices
// are copied and keep their nilness, so a nil Settings still sends Go's
// SETTINGS.
func (h HTTP2) Clone() HTTP2 {
	h.Settings = slices.Clone(h.Settings)
	h.InitPriorityFrames = slices.Clone(h.InitPriorityFrames)

	return h
}
