package catalog

import (
	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// chromiumNetPriority is a Chromium net::RequestPriority.
type chromiumNetPriority uint8

// Chromium request priorities, lowest first, as in net/base/request_priority.h.
const (
	chromiumIdle chromiumNetPriority = iota + 1
	chromiumLowest
	chromiumLow
	chromiumMedium
	chromiumHighest
)

// urgency maps a net priority to an RFC 9218 urgency: HIGHEST is 0 and IDLE
// is 4.
func (p chromiumNetPriority) urgency() int {
	return int(chromiumHighest - p)
}

// wireWeight returns the HTTP/2 weight Chromium derives from a net priority
// (Spdy3PriorityToHttp2Weight) as a wire value: effective weights 256, 220,
// 183, 147, and 110, each minus one.
func (p chromiumNetPriority) wireWeight() uint8 {
	switch p {
	case chromiumHighest:
		return 255
	case chromiumMedium:
		return 219
	case chromiumLow:
		return 182
	case chromiumLowest:
		return 146
	default:
		return 109
	}
}

// chromiumRequest is how Chromium prioritizes one kind of request.
type chromiumRequest struct {
	// priority is the net priority Blink's TypeToPriority or the browser
	// assigns.
	priority chromiumNetPriority

	// incremental is the Priority field's incremental flag
	// (ShouldLoadIncremental; true for requests Blink does not classify).
	incremental bool
}

// chromiumRequests maps destinations to Chromium's default priority for
// them, from Blink's resource_fetcher.cc and resource_request_utils.cc and
// the browser's navigation and worker loaders.
//
// Service worker scripts are absent because their request construction was
// not traced.
var chromiumRequests = map[fetchDestination]chromiumRequest{
	// Main-frame and subframe navigations are always HIGHEST.
	destinationDocument: {
		priority:    chromiumHighest,
		incremental: true,
	},
	destinationSubframe: {
		priority:    chromiumHighest,
		incremental: true,
	},

	// Object and embed elements load into a content frame, a navigation.
	destinationObject: {
		priority:    chromiumHighest,
		incremental: true,
	},
	destinationEmbed: {
		priority:    chromiumHighest,
		incremental: true,
	},

	// fetch() and XMLHttpRequest load raw resources.
	destinationEmpty: {
		priority:    chromiumMedium,
		incremental: true,
	},

	// A parser-blocking classic script found early; async, defer, and
	// script-inserted classic scripts drop to LOWEST.
	destinationScript: {
		priority: chromiumMedium,
	},

	// Stylesheets and fonts are Blink's VeryHigh, which maps to HIGHEST.
	destinationStyle: {
		priority: chromiumHighest,
	},
	destinationFont: {
		priority: chromiumHighest,
	},

	// An image that is not visible yet; a visible image is MEDIUM.
	destinationImage: {
		priority:    chromiumLowest,
		incremental: true,
	},

	destinationAudio: {
		priority:    chromiumLowest,
		incremental: true,
	},
	destinationVideo: {
		priority:    chromiumLowest,
		incremental: true,
	},
	destinationTrack: {
		priority:    chromiumLowest,
		incremental: true,
	},
	destinationManifest: {
		priority: chromiumLow,
	},

	// Dedicated and shared worker scripts keep the ResourceRequest default.
	destinationWorker: {
		priority:    chromiumIdle,
		incremental: true,
	},
	destinationSharedWorker: {
		priority:    chromiumIdle,
		incremental: true,
	},

	// CSP violation reports are raw resources lowered to IDLE.
	destinationReport: {
		priority:    chromiumIdle,
		incremental: true,
	},

	destinationXSLT: {
		priority: chromiumMedium,
	},
}

// chromiumPriority returns Chromium's priority for a destination. HEADERS
// always carry an exclusive priority on the root, the dependency of the
// first request on a connection. The Priority field travels on HTTP/2 only,
// from Chromium 124.
//
// Destinations missing from chromiumRequests keep fphttp v1's behavior: the
// document's HTTP/2 priority and no Priority field.
func (e Entry) chromiumPriority(destination fetchDestination) RequestPriority {
	request, ok := chromiumRequests[destination]
	if !ok {
		return RequestPriority{HTTP2: e.Wire.HTTP2.HeaderPriority}
	}

	priority := RequestPriority{
		HTTP2: fingerprint.Priority{
			Enabled:   true,
			Exclusive: true,
			Weight:    request.priority.wireWeight(),
		},
	}

	if e.Wire.chromiumFeatures != nil && e.Wire.chromiumFeatures.PriorityHeader {
		priority.Field = priorityField(request.priority.urgency(), request.incremental)
	}

	return priority
}
