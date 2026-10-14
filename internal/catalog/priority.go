package catalog

import (
	"strconv"

	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// defaultUrgency is the RFC 9218 urgency a Priority field omits.
const defaultUrgency = 3

// RequestPriority is how a browser prioritizes one request.
type RequestPriority struct {
	// HTTP2 is the priority of the request's HTTP/2 HEADERS frame. Enabled
	// false omits the PRIORITY flag. Weight is the wire value, one less than
	// the effective weight.
	HTTP2 fingerprint.Priority

	// Field is the extensible Priority field value (RFC 9218), such as
	// "u=0, i". Empty means the field is not sent.
	Field string

	// FieldOnHTTP1 reports that Field is also sent on HTTP/1.1. Firefox
	// sends it on HTTP/1.1 and HTTP/2; Chromium and Safari send it on
	// HTTP/2 only.
	FieldOnHTTP1 bool
}

// Priority returns how the release prioritizes a request for destination
// (see Accept), as the browser does on a typical page: an active tab, no
// fetchpriority attribute, fetch() rather than XMLHttpRequest, a
// parser-blocking script, and an image that is not visible yet. The
// document priority equals Wire.HTTP2.HeaderPriority. It returns the zero
// RequestPriority for an unknown destination.
func (e Entry) Priority(destination string) RequestPriority {
	kind := parseDestination(destination)
	if kind == destinationUnknown || e.Wire == nil {
		return RequestPriority{}
	}

	switch e.Family {
	case FamilyChromium:
		return e.chromiumPriority(kind)
	case FamilyFirefox:
		return e.firefoxPriority(kind)
	case FamilySafari:
		return safariPriority(kind)
	default:
		return RequestPriority{}
	}
}

// priorityField serializes a Priority field the way Chromium and Firefox
// do: the urgency is omitted at its default of 3, "i" marks an incremental
// response, and an empty result means the field is not sent.
func priorityField(urgency int, incremental bool) string {
	field := ""
	if urgency != defaultUrgency {
		field = "u=" + strconv.Itoa(urgency)
	}

	switch {
	case !incremental:
		return field
	case field == "":
		return "i"
	default:
		return field + ", i"
	}
}
