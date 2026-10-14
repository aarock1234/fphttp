package catalog

import (
	"slices"

	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// Chromium HTTP/2 connection values (net/spdy and net/http defaults).
const (
	chromiumHeaderTableSize   = 65536
	chromiumInitialWindowSize = 6291456
	chromiumMaxHeaderListSize = 262144
	chromiumConnectionFlow    = 15663105

	// chromiumMaxConcurrentStreamsIndex is where Chromium 108 to 116 place
	// MAX_CONCURRENT_STREAMS in SETTINGS.
	chromiumMaxConcurrentStreamsIndex = 2

	// chromiumDocumentWeight is the wire weight of a HIGHEST priority
	// request (effective weight 256).
	chromiumDocumentWeight = 255
)

// Firefox HTTP/2 connection values. Desktop values are the Necko defaults;
// Android values come from GeckoView's network.http.http2.default-hpack-buffer
// and network.http.http2.push-allowance preferences.
const (
	firefoxDesktopHeaderTableSize   = 65536
	firefoxDesktopInitialWindowSize = 131072
	firefoxAndroidHeaderTableSize   = 4096
	firefoxAndroidInitialWindowSize = 32768
	firefoxMaxFrameSize             = 16384
	firefoxConnectionFlow           = 12517377

	// firefoxTreeInitialStreamID is the first request stream after the six
	// legacy-tree PRIORITY frames on streams 3 to 13.
	firefoxTreeInitialStreamID = 15

	// firefoxInitialStreamID is the first request stream without the tree.
	firefoxInitialStreamID = 3

	// firefoxUrgentStartGroup is the legacy-tree group stream that
	// top-level documents depend on.
	firefoxUrgentStartGroup = 13

	// firefoxDocumentWeight is the HEADERS weight byte of a top-level
	// document: 21 minus its channel priority of -20.
	firefoxDocumentWeight = 41
)

// Safari HTTP/2 connection values from the Safari 26 and 27 captures.
const (
	safariMaxConcurrentStreams = 100
	safariInitialWindowSize    = 2097152
	safariConnectionFlow       = 10420225
)

// firefoxPriorityTree is the legacy RFC 7540 dependency tree Firefox sends
// after SETTINGS and WINDOW_UPDATE: leader, other, background, speculative,
// follower, and urgent-start groups. Shared by every legacy-tree wire.
var firefoxPriorityTree = []fingerprint.PriorityFrame{
	{
		StreamID:  3,
		StreamDep: 0,
		Weight:    200,
	},
	{
		StreamID:  5,
		StreamDep: 0,
		Weight:    100,
	},
	{
		StreamID:  7,
		StreamDep: 0,
		Weight:    0,
	},
	{
		StreamID:  9,
		StreamDep: 7,
		Weight:    0,
	},
	{
		StreamID:  11,
		StreamDep: 3,
		Weight:    0,
	},
	{
		StreamID:  13,
		StreamDep: 0,
		Weight:    240,
	},
}

// chromiumHTTP2 returns the HTTP/2 template of a Chromium feature set.
// HeaderPriority models a top-level document: HIGHEST, exclusive, on the
// root.
func chromiumHTTP2(features *ChromiumWire) fingerprint.HTTP2 {
	settings := []fingerprint.Setting{
		{
			ID:  fingerprint.SettingHeaderTableSize,
			Val: chromiumHeaderTableSize,
		},
		{
			ID:  fingerprint.SettingEnablePush,
			Val: 0,
		},
		{
			ID:  fingerprint.SettingInitialWindowSize,
			Val: chromiumInitialWindowSize,
		},
		{
			ID:  fingerprint.SettingMaxHeaderListSize,
			Val: chromiumMaxHeaderListSize,
		},
	}

	if features.MaxConcurrentStreams != 0 {
		settings = slices.Insert(settings, chromiumMaxConcurrentStreamsIndex, fingerprint.Setting{
			ID:  fingerprint.SettingMaxConcurrentStreams,
			Val: features.MaxConcurrentStreams,
		})
	}

	return fingerprint.HTTP2{
		Settings:       settings,
		ConnectionFlow: chromiumConnectionFlow,
		HeaderPriority: fingerprint.Priority{
			Enabled:   true,
			Exclusive: true,
			Weight:    chromiumDocumentWeight,
		},
	}
}

// firefoxHTTP2 returns the HTTP/2 template of a Firefox feature set.
//
// Firefox always sets the PRIORITY flag on HEADERS. HeaderPriority models a
// top-level document: weight byte 41, depending on the urgent-start group
// with the legacy tree and on the root without it. The exclusive bit is
// never set.
func firefoxHTTP2(features *FirefoxWire) fingerprint.HTTP2 {
	h2 := fingerprint.HTTP2{
		Settings:        firefoxSettings(features),
		ConnectionFlow:  firefoxConnectionFlow,
		InitialStreamID: firefoxInitialStreamID,
		HeaderPriority: fingerprint.Priority{
			Enabled: true,
			Weight:  firefoxDocumentWeight,
		},
	}

	if features.LegacyTree {
		h2.InitialStreamID = firefoxTreeInitialStreamID
		h2.InitPriorityFrames = firefoxPriorityTree
		h2.HeaderPriority.StreamDep = firefoxUrgentStartGroup
	}

	return h2
}

// firefoxSettings returns the SETTINGS a Firefox feature set sends, in wire
// order.
//
// ENABLE_PUSH is always 0 because the transport cannot accept server push.
// Legacy-tree releases really omitted it, since push was allowed by default;
// with the push preference off they send ENABLE_PUSH 0 and
// MAX_CONCURRENT_STREAMS 0, which is what these wires model.
func firefoxSettings(features *FirefoxWire) []fingerprint.Setting {
	headerTableSize := uint32(firefoxDesktopHeaderTableSize)
	initialWindowSize := uint32(firefoxDesktopInitialWindowSize)
	if features.Android {
		headerTableSize = firefoxAndroidHeaderTableSize
		initialWindowSize = firefoxAndroidInitialWindowSize
	}

	settings := []fingerprint.Setting{
		{
			ID:  fingerprint.SettingHeaderTableSize,
			Val: headerTableSize,
		},
		{
			ID:  fingerprint.SettingEnablePush,
			Val: 0,
		},
	}

	if features.LegacyTree {
		settings = append(settings, fingerprint.Setting{
			ID:  fingerprint.SettingMaxConcurrentStreams,
			Val: 0,
		})
	}

	settings = append(settings,
		fingerprint.Setting{
			ID:  fingerprint.SettingInitialWindowSize,
			Val: initialWindowSize,
		},
		fingerprint.Setting{
			ID:  fingerprint.SettingMaxFrameSize,
			Val: firefoxMaxFrameSize,
		},
	)

	if features.NoRFC7540Priorities && !features.LegacyTree {
		settings = append(settings, fingerprint.Setting{
			ID:  fingerprint.SettingNoRFC7540Priorities,
			Val: 1,
		})
	}

	return settings
}

// safariHTTP2 returns the captured Safari 26 and 27 HTTP/2 template. Safari
// signals priority only through the extensible Priority field, so HEADERS
// carry no priority.
func safariHTTP2() fingerprint.HTTP2 {
	return fingerprint.HTTP2{
		Settings: []fingerprint.Setting{
			{
				ID:  fingerprint.SettingEnablePush,
				Val: 0,
			},
			{
				ID:  fingerprint.SettingMaxConcurrentStreams,
				Val: safariMaxConcurrentStreams,
			},
			{
				ID:  fingerprint.SettingInitialWindowSize,
				Val: safariInitialWindowSize,
			},
			{
				ID:  fingerprint.SettingNoRFC7540Priorities,
				Val: 1,
			},
		},
		ConnectionFlow: safariConnectionFlow,
	}
}
