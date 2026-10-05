// Package fingerprint defines the wire configuration shared by the HTTP stack.
package fingerprint

import (
	"errors"
	"fmt"
	"math"
	"net/textproto"
	"slices"

	"golang.org/x/net/http/httpguts"
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

// Validate checks the dependency's range and, when known, the stream ID.
func (p Priority) Validate(streamID uint32) error {
	if !p.Enabled {
		return nil
	}
	if p.StreamDep > math.MaxInt32 {
		return errors.New("fphttp: HEADERS priority dependency exceeds 2147483647")
	}
	if streamID != 0 && p.StreamDep == streamID {
		return errors.New("fphttp: a HEADERS frame cannot depend on its own stream")
	}

	return nil
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

// HTTP2 configures the initial HTTP/2 connection frames.
type HTTP2 struct {
	// Settings replaces the initial SETTINGS frame when non-nil.
	// It must explicitly disable server push, which this client does not support.
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

// Config is the fingerprint configuration consumed by the HTTP/2 transport.
type Config struct {
	// HeaderOrder lists canonical regular header names in wire order.
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

// Validate rejects configurations that cannot be sent or honored safely.
func (h HTTP2) Validate() error {
	var problems []error
	seen := make(map[SettingID]bool, len(h.Settings))

	for _, setting := range h.Settings {
		if seen[setting.ID] {
			problems = append(problems, fmt.Errorf("fphttp: duplicate H2 setting ID %v", setting.ID))
		}
		seen[setting.ID] = true

		switch setting.ID {
		case SettingEnablePush:
			if setting.Val != 0 {
				problems = append(problems, errors.New("fphttp: ENABLE_PUSH must be 0; server push is unsupported"))
			}
		case SettingInitialWindowSize:
			if setting.Val == 0 || setting.Val > math.MaxInt32 {
				problems = append(problems, errors.New("fphttp: INITIAL_WINDOW_SIZE must be between 1 and 2147483647"))
			}
		case SettingMaxFrameSize:
			if setting.Val < 16384 || setting.Val > 16777215 {
				problems = append(problems, errors.New("fphttp: MAX_FRAME_SIZE must be between 16384 and 16777215"))
			}
		case SettingMaxHeaderListSize:
			if setting.Val == 0 {
				problems = append(problems, errors.New("fphttp: MAX_HEADER_LIST_SIZE must allow response headers"))
			}
		case SettingEnableConnectProtocol, SettingNoRFC7540Priorities:
			if setting.Val > 1 {
				problems = append(problems, fmt.Errorf("fphttp: %v must be 0 or 1", setting.ID))
			}
		}
	}

	if h.Settings != nil && !seen[SettingEnablePush] {
		problems = append(problems, errors.New("fphttp: custom H2 settings must include ENABLE_PUSH = 0"))
	}
	if h.ConnectionFlow > math.MaxInt32-65535 {
		problems = append(problems, errors.New("fphttp: ConnectionFlow plus the initial window exceeds 2147483647"))
	}
	if h.InitialStreamID != 0 && (h.InitialStreamID%2 == 0 || h.InitialStreamID > math.MaxInt32) {
		problems = append(problems, errors.New("fphttp: InitialStreamID must be an odd 31-bit stream ID"))
	}
	firstStreamID := h.InitialStreamID
	if firstStreamID == 0 {
		firstStreamID = 1
	}
	if err := h.HeaderPriority.Validate(firstStreamID); err != nil {
		problems = append(problems, err)
	}

	for i, priority := range h.InitPriorityFrames {
		if priority.StreamID == 0 || priority.StreamID > math.MaxInt32 {
			problems = append(problems, fmt.Errorf("fphttp: InitPriorityFrames[%d] requires a non-zero 31-bit StreamID", i))
		}
		if priority.StreamDep > math.MaxInt32 || priority.StreamDep == priority.StreamID {
			problems = append(problems, fmt.Errorf("fphttp: InitPriorityFrames[%d] has an invalid StreamDep", i))
		}
	}

	if value, _ := h.SettingValue(SettingNoRFC7540Priorities); value == 1 {
		if h.HeaderPriority.Enabled || len(h.InitPriorityFrames) > 0 {
			problems = append(problems, errors.New("fphttp: NO_RFC7540_PRIORITIES = 1 conflicts with legacy priority frames"))
		}
	}

	return errors.Join(problems...)
}

// ValidateHeaderOrder checks canonical field names and duplicates.
func ValidateHeaderOrder(order []string) error {
	var problems []error
	seen := make(map[string]bool, len(order))

	for _, name := range order {
		switch {
		case !httpguts.ValidHeaderFieldName(name):
			problems = append(problems, fmt.Errorf("fphttp: HeaderOrder contains invalid field name %q", name))
		case textproto.CanonicalMIMEHeaderKey(name) != name:
			problems = append(problems, fmt.Errorf("fphttp: HeaderOrder key %q is not canonical, use %q", name, textproto.CanonicalMIMEHeaderKey(name)))
		case seen[name]:
			problems = append(problems, fmt.Errorf("fphttp: HeaderOrder contains duplicate %q", name))
		}
		seen[name] = true
	}

	return errors.Join(problems...)
}

// ValidatePseudoHeaderOrder checks all four request pseudo-headers.
// An empty order selects the standard Go order.
func ValidatePseudoHeaderOrder(order []string) error {
	if len(order) == 0 {
		return nil
	}

	required := []string{":method", ":authority", ":scheme", ":path"}
	var problems []error
	seen := make(map[string]bool, len(required))

	for _, name := range order {
		switch {
		case !slices.Contains(required, name):
			problems = append(problems, fmt.Errorf("fphttp: PseudoHeaderOrder contains invalid pseudo-header %q", name))
		case seen[name]:
			problems = append(problems, fmt.Errorf("fphttp: PseudoHeaderOrder contains duplicate %q", name))
		}
		seen[name] = true
	}
	for _, name := range required {
		if !seen[name] {
			problems = append(problems, fmt.Errorf("fphttp: PseudoHeaderOrder missing required pseudo-header %q", name))
		}
	}

	return errors.Join(problems...)
}

// ResolveOrder prefers an explicitly supplied request order.
func ResolveOrder(request, fallback []string) []string {
	if request != nil {
		return request
	}

	return fallback
}
