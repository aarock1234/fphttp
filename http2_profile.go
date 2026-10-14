package http

import "github.com/aarock1234/fphttp/v2/internal/fingerprint"

// H2SettingID identifies an HTTP/2 SETTINGS parameter in
// HTTP2Profile.Settings.
type H2SettingID = fingerprint.SettingID

// HTTP/2 SETTINGS parameters that an HTTP2Profile can send (RFC 9113,
// section 6.5.2, and RFC 9218).
const (
	// H2SettingHeaderTableSize is SETTINGS_HEADER_TABLE_SIZE (0x1), the
	// HPACK decoder table size the client accepts.
	H2SettingHeaderTableSize = fingerprint.SettingHeaderTableSize

	// H2SettingEnablePush is SETTINGS_ENABLE_PUSH (0x2). It must be 0,
	// because fphttp does not support server push.
	H2SettingEnablePush = fingerprint.SettingEnablePush

	// H2SettingMaxConcurrentStreams is SETTINGS_MAX_CONCURRENT_STREAMS (0x3).
	H2SettingMaxConcurrentStreams = fingerprint.SettingMaxConcurrentStreams

	// H2SettingInitialWindowSize is SETTINGS_INITIAL_WINDOW_SIZE (0x4), the
	// receive window of each stream.
	H2SettingInitialWindowSize = fingerprint.SettingInitialWindowSize

	// H2SettingMaxFrameSize is SETTINGS_MAX_FRAME_SIZE (0x5), the largest
	// frame the client accepts.
	H2SettingMaxFrameSize = fingerprint.SettingMaxFrameSize

	// H2SettingMaxHeaderListSize is SETTINGS_MAX_HEADER_LIST_SIZE (0x6), the
	// largest response header block the client accepts.
	H2SettingMaxHeaderListSize = fingerprint.SettingMaxHeaderListSize

	// H2SettingEnableConnectProtocol is SETTINGS_ENABLE_CONNECT_PROTOCOL
	// (0x8), 0 or 1.
	H2SettingEnableConnectProtocol = fingerprint.SettingEnableConnectProtocol

	// H2SettingNoRFC7540Priorities is SETTINGS_NO_RFC7540_PRIORITIES (0x9),
	// 0 or 1. A value of 1 cannot be combined with
	// HTTP2Profile.InitPriorityFrames.
	H2SettingNoRFC7540Priorities = fingerprint.SettingNoRFC7540Priorities
)

// H2Setting is one HTTP/2 SETTINGS parameter and its value. A list of them
// is sent in its own order.
type H2Setting = fingerprint.Setting

// H2Priority is the optional priority signal in a HEADERS frame.
// Weight is the wire value, from 0 to 255, representing weights 1 to 256.
type H2Priority = fingerprint.Priority

// H2PriorityFrame is a standalone PRIORITY frame sent after the HTTP/2
// connection preface.
type H2PriorityFrame = fingerprint.PriorityFrame
