package catalog

import (
	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// Firefox channel priorities (nsISupportsPriority). Lower values are more
// urgent.
const (
	firefoxPriorityHighest = -20
	firefoxPriorityHigh    = -10
	firefoxPriorityNormal  = 0
	firefoxPriorityLow     = 10
	firefoxPriorityLowest  = 20
)

const (
	// firefoxWeightBase gives the HEADERS weight byte: firefoxWeightBase
	// minus the channel priority, so HIGHEST is 41 and LOW is 11.
	firefoxWeightBase = firefoxPriorityLowest + 1

	// firefoxMaxUrgency is the least urgent value Firefox sends.
	firefoxMaxUrgency = 6
)

// Firefox majors where request priority changes.
const (
	// firefoxPriorityFieldMajor sends the Priority field
	// (network.http.priority_header.enabled). ESR 102 and 115 never do.
	firefoxPriorityFieldMajor = 126

	// firefoxAdjustedUrgencyMajor adjusts urgency by channel priority
	// (network.fetchpriority.adjust_urgency) and marks documents and images
	// incremental.
	firefoxAdjustedUrgencyMajor = 128
)

// firefoxClass is a Necko class of service.
type firefoxClass struct {
	// group is the legacy-tree group stream that HEADERS depend on.
	group uint32

	// urgency is the class's base Priority urgency.
	urgency int
}

// Firefox classes of service used by the cataloged destinations.
var (
	// firefoxUrgentStart is a top-level document load.
	firefoxUrgentStart = firefoxClass{
		group:   13,
		urgency: 1,
	}

	// firefoxLeader is a render-blocking stylesheet or head script.
	firefoxLeader = firefoxClass{
		group:   3,
		urgency: 2,
	}

	// firefoxUnclassified is a request without class flags, which depends
	// on the follower group.
	firefoxUnclassified = firefoxClass{
		group:   11,
		urgency: 4,
	}

	// firefoxUnblocked is a request that head CSS and scripts never block,
	// such as a WebSocket handshake; it depends on the "other" group
	// (GetPriorityDependencyFromTransaction).
	firefoxUnblocked = firefoxClass{
		group:   5,
		urgency: 3,
	}
)

// firefoxRequest is how Firefox's loaders classify one kind of request.
type firefoxRequest struct {
	// class is the request's class of service.
	class firefoxClass

	// priority is the channel priority.
	priority int

	// incremental marks the response incremental from Firefox 128.
	incremental bool
}

// firefoxRequests maps destinations to the class and priority Firefox's
// loaders assign, from nsDocShell, css::Loader, ScriptLoader, imgLoader,
// FontPreloader and FontLoaderUtils, FetchDriver, and WebSocketChannel.
//
// Iframes, media, tracks, manifests, objects, embeds, workers, reports, and
// XSLT are absent because their loaders were not traced.
var firefoxRequests = map[fetchDestination]firefoxRequest{
	destinationDocument: {
		class:       firefoxUrgentStart,
		priority:    firefoxPriorityHighest,
		incremental: true,
	},

	destinationStyle: {
		class:    firefoxLeader,
		priority: firefoxPriorityNormal,
	},

	// A parser-blocking script in <head>; async, deferred, and body
	// scripts are Unblocked instead.
	destinationScript: {
		class:    firefoxLeader,
		priority: firefoxPriorityNormal,
	},

	destinationImage: {
		class:       firefoxUnclassified,
		priority:    firefoxPriorityLow,
		incremental: true,
	},

	// @font-face loads raise the channel to HIGH and forbid tailing:
	// FontPreloader at ESR 102.15.1, 108, and 115, and FontLoaderUtils at
	// 144.
	destinationFont: {
		class:    firefoxUnclassified,
		priority: firefoxPriorityHigh,
	},

	// fetch(); XMLHttpRequest is Unblocked instead.
	destinationEmpty: {
		class:    firefoxUnclassified,
		priority: firefoxPriorityNormal,
	},

	// WebSocketChannel::SetupRequest marks the handshake Unblocked, and
	// Http2Session creates its stream at PRIORITY_NORMAL. Urgency 3 without
	// "i" serializes to nothing, so it sends no Priority field.
	destinationWebSocket: {
		class:    firefoxUnblocked,
		priority: firefoxPriorityNormal,
	},
}

// firefoxPriority returns Firefox's priority for a destination. HEADERS
// always carry the PRIORITY flag, never exclusive, depending on the class
// group with the legacy tree and on the root without it. The Priority field
// travels on HTTP/1.1 and HTTP/2 from Firefox 126.
//
// Destinations missing from firefoxRequests keep fphttp v1's behavior: the
// document's HEADERS priority and no Priority field. Unlike v1, that
// priority always carries the PRIORITY flag, which source verifies for every
// Firefox HEADERS frame.
func (e Entry) firefoxPriority(destination fetchDestination) RequestPriority {
	request, ok := firefoxRequests[destination]
	if !ok {
		return RequestPriority{HTTP2: e.Wire.HTTP2.HeaderPriority}
	}

	priority := RequestPriority{
		HTTP2: fingerprint.Priority{
			Enabled: true,
			Weight:  request.weight(),
		},
	}

	if e.Wire.firefoxFeatures != nil && e.Wire.firefoxFeatures.LegacyTree {
		priority.HTTP2.StreamDep = request.class.group
	}

	major := e.Major()
	if major < firefoxPriorityFieldMajor {
		return priority
	}

	priority.Field = request.field(major >= firefoxAdjustedUrgencyMajor)
	priority.FieldOnHTTP1 = priority.Field != ""

	return priority
}

// weight returns the HEADERS weight byte.
func (r firefoxRequest) weight() uint8 {
	return uint8(firefoxWeightBase - r.priority)
}

// field returns the Priority field value. Before 128 it carries the class
// urgency alone; from 128 the channel priority adjusts the urgency and
// incremental requests add "i".
func (r firefoxRequest) field(adjusted bool) string {
	if !adjusted {
		return priorityField(r.class.urgency, false)
	}

	urgency := r.class.urgency + firefoxUrgencyAdjustment(r.priority)
	urgency = min(max(urgency, 0), firefoxMaxUrgency)

	return priorityField(urgency, r.incremental)
}

// firefoxUrgencyAdjustment returns how much a channel priority moves the
// urgency: HIGHEST -2, HIGH -1, LOW +1, LOWEST +2.
func firefoxUrgencyAdjustment(priority int) int {
	switch priority {
	case firefoxPriorityHighest:
		return -2
	case firefoxPriorityHigh:
		return -1
	case firefoxPriorityLow:
		return 1
	case firefoxPriorityLowest:
		return 2
	default:
		return 0
	}
}
