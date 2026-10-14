package http

import (
	"slices"

	"github.com/aarock1234/fphttp/v2/internal/catalog"
	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// selectHTTP2Priority gives a prepared request whose H2Priority is nil the
// HTTP/2 HEADERS priority the release uses for its Destination (catalog
// Entry.Priority). It runs whether or not the profile generates fields,
// because the HEADERS priority is part of the HTTP/2 wire, not a field.
//
// A top-level page load keeps a nil H2Priority, which the HTTP/2 transport
// resolves to Profile.HTTP2.HeaderPriority, the document priority. Other
// destinations take the catalog's priority while it describes the profile
// (see usesCatalogPriorities), and otherwise keep the document priority too.
func (t *Transport) selectHTTP2Priority(request *Request) {
	state := &t.profileState
	if request.H2Priority != nil || request.Destination.topLevel() || !state.catalogPriorities {
		return
	}

	priority := state.snapshot.entry.Priority(string(request.Destination)).HTTP2
	request.H2Priority = &priority
	request.profileHop.catalogH2Priority = true
}

// usesChromiumDependencies reports whether the HTTP/2 transport chains the
// HEADERS frames of profile-priority requests the way Chromium does (see
// fingerprint.Config.ChromiumDependencies). It requires a Chromium release
// whose priority configuration is still the catalog's, so a profile whose
// HeaderPriority was changed, for example to a fixed dependency, sends
// exactly what it was configured with.
func (t *Transport) usesChromiumDependencies() bool {
	state := &t.profileState

	return state.catalogPriorities && state.snapshot.family() == catalog.FamilyChromium
}

// priority adds the extensible Priority field the release sends for the
// request's Destination (catalog Entry.Priority).
func (g *fieldGenerator) priority() {
	g.priorityField(g.entry.Priority(g.destination()))
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
