package http

import (
	"slices"

	"github.com/aarock1234/fphttp/v2/internal/catalog"
	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// priority applies how the release prioritizes a request for its
// Destination (catalog Entry.Priority): the HTTP/2 HEADERS priority and the
// extensible Priority field.
func (g *fieldGenerator) priority() {
	priority := g.entry.Priority(g.destination())

	g.http2Priority(priority.HTTP2)
	g.priorityField(priority)
}

// http2Priority gives a request whose H2Priority is nil the HEADERS priority
// the release uses for its Destination.
//
// A top-level page load keeps a nil H2Priority, which the HTTP/2 transport
// resolves to Profile.HTTP2.HeaderPriority, the document priority. Other
// destinations take the catalog's priority while it describes the profile
// (see usesCatalogPriorities), and otherwise keep the document priority too.
func (g *fieldGenerator) http2Priority(priority fingerprint.Priority) {
	request := g.request
	if request.H2Priority != nil || request.Destination.topLevel() || !g.catalogPriorities {
		return
	}

	request.H2Priority = &priority
}

// priorityField adds the release's extensible Priority field (RFC 9218) for
// the request's Destination, unless the request sets a Priority field or
// H2PriorityHeader itself. A release that also sends the field on HTTP/1.1,
// as Firefox does, gets a regular Priority field. A release that sends it on
// HTTP/2 only, as Chromium and Safari do, gets H2PriorityHeader, which only
// the HTTP/2 transport writes.
func (g *fieldGenerator) priorityField(priority catalog.RequestPriority) {
	request := g.request
	if priority.Field == "" || g.has("Priority") || request.H2PriorityHeader != "" {
		return
	}

	if priority.FieldOnHTTP1 {
		g.addMissing("Priority", priority.Field)

		return
	}

	request.H2PriorityHeader = priority.Field
}

// usesCatalogPriorities reports whether the catalog's per-destination HTTP/2
// priorities describe snapshot. They do while snapshot has a release
// identity and still has the release wire's settings that the priorities
// depend on: the document HeaderPriority, InitialStreamID,
// InitPriorityFrames, and NO_RFC7540_PRIORITIES.
//
// A profile whose priority configuration was changed, for example to turn
// RFC 7540 priorities off or to drop the PRIORITY frames whose streams
// Firefox's priorities depend on, sends its own document priority on every
// request instead, so it never sends a priority it was configured without.
func usesCatalogPriorities(snapshot *Profile) bool {
	if !snapshot.hasIdentity() || snapshot.entry.Wire == nil {
		return false
	}

	profile := snapshot.HTTP2
	wire := snapshot.entry.Wire.HTTP2

	return profile.HeaderPriority == wire.HeaderPriority &&
		profile.InitialStreamID == wire.InitialStreamID &&
		slices.Equal(profile.InitPriorityFrames, wire.InitPriorityFrames) &&
		noRFC7540Priorities(profile) == noRFC7540Priorities(wire)
}

// noRFC7540Priorities returns the NO_RFC7540_PRIORITIES setting of config,
// zero when it is not sent.
func noRFC7540Priorities(config fingerprint.HTTP2) uint32 {
	value, _ := config.SettingValue(fingerprint.SettingNoRFC7540Priorities)

	return value
}
