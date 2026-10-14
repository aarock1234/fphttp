package http

import (
	"github.com/aarock1234/fphttp/v2/internal/catalog"
	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// fieldGenerator generates the browser fields of one hop of a prepared
// request. Values come from the release's catalog entry; when a field is
// sent follows the browser rules fphttp v1 established.
//
// A field is generated only when the request does not set it: its Header
// has canonical keys and already holds the caller's and the profile's
// fields, so a present but empty value suppresses the field.
type fieldGenerator struct {
	// request is the prepared request whose Header receives the fields.
	request *Request

	// chain is the request's redirect chain, oldest first and ending with
	// request (see Request.redirectChain).
	chain []*Request

	// entry is the release whose values the fields carry.
	entry *catalog.Entry

	// target classifies the request URL (see targetKind).
	target catalog.URLKind

	// keepAlive reports that the Transport reuses connections, so an
	// HTTP/1.1 request may ask to keep its connection open.
	keepAlive bool

	// hintValues holds the release's client hint values, or nil when the
	// release sends no client hints.
	hintValues *catalog.ClientHints

	// hintStore remembers the client hints each origin asked for.
	hintStore *clientHintStore
}

// newFieldGenerator returns the generator for a prepared request of a
// Transport whose profile generates fields (see Profile.generatesFields).
func (t *Transport) newFieldGenerator(request *Request, chain []*Request) *fieldGenerator {
	state := &t.profileState

	return &fieldGenerator{
		request:    request,
		chain:      chain,
		entry:      state.snapshot.entry,
		target:     targetKind(request.URL),
		keepAlive:  !t.DisableKeepAlives,
		hintValues: state.hintValues,
		hintStore:  state.hints,
	}
}

// generate adds every browser field the request lacks.
func (g *fieldGenerator) generate() {
	g.contentFields()
	g.upgradeInsecureRequests()
	g.fetchMetadata()
	g.originField()
	g.refererField()
	g.clientHints()
	g.requestFields()
	g.connectionField()
	g.priority()
	g.http2OnlyFields()
}

// destination returns the request's Destination in the form the catalog
// takes, a Sec-Fetch-Dest value or "" for a top-level page load.
func (g *fieldGenerator) destination() string {
	return string(g.request.Destination)
}

// has reports whether the request sets the canonical field name, including
// with a present but empty value.
func (g *fieldGenerator) has(name string) bool {
	_, present := g.request.Header[name]

	return present
}

// addMissing sets the canonical field name to value when value is not
// empty and the request does not set the field. It reports whether it added
// the field.
func (g *fieldGenerator) addMissing(name, value string) bool {
	if value == "" || g.has(name) {
		return false
	}

	g.request.Header[name] = []string{value}

	return true
}

// trustworthy reports whether the request URL is potentially trustworthy
// (see potentiallyTrustworthy).
func (g *fieldGenerator) trustworthy() bool {
	return g.target != catalog.URLInsecure
}

// webSocket reports whether the request is a WebSocket handshake.
func (g *fieldGenerator) webSocket() bool {
	return g.request.Destination == DestinationWebSocket
}

// contentFields adds Accept, Accept-Encoding, and the Range of an audio or
// video request. A generated Accept-Encoding is recorded, because the
// response body is then encoded as the profile asked.
func (g *fieldGenerator) contentFields() {
	destination := g.destination()

	g.addMissing("Accept", g.entry.Accept(destination))

	if g.addMissing("Accept-Encoding", g.acceptEncoding()) {
		g.request.profileHop.acceptEncoding = true
	}

	g.addMissing("Range", g.entry.Range(destination))
}

// acceptEncoding returns the release's Accept-Encoding for the request.
// Chromium asks for identity instead when the request carries a Range
// field, because a byte range of an encoded body cannot be decoded. Audio
// and video keep their own value, which Chromium's media loader sets
// together with its Range field.
func (g *fieldGenerator) acceptEncoding() string {
	chromium := g.entry.Family == catalog.FamilyChromium
	rangeOutsideMedia := g.sendsRange() && !g.request.Destination.media()

	if chromium && rangeOutsideMedia {
		return "identity"
	}

	return g.entry.AcceptEncoding(g.destination(), g.target)
}

// sendsRange reports whether the request carries a non-empty Range field.
func (g *fieldGenerator) sendsRange() bool {
	return !emptyFieldValues(g.request.Header["Range"])
}

// upgradeInsecureRequests adds Upgrade-Insecure-Requests, which Chromium and
// Firefox send on document and iframe loads to http and https URLs alike.
func (g *fieldGenerator) upgradeInsecureRequests() {
	g.addMissing("Upgrade-Insecure-Requests", g.entry.UpgradeInsecureRequests(g.destination()))
}

// requestFields adds the other fields the release sends for the request's
// Destination (catalog Entry.RequestFields), such as Brave's Sec-GPC and
// the Service-Worker field of a service worker script.
func (g *fieldGenerator) requestFields() {
	for _, field := range g.entry.RequestFields(g.destination()) {
		g.addMissing(CanonicalHeaderKey(field.Name), field.Value)
	}
}

// connectionField adds Connection: keep-alive, which Chromium and Firefox
// send on every HTTP/1.1 request; HTTP/2 drops the field. It is not added
// when the request or the Transport closes the connection, because Go then
// sends Connection: close. A generated field is recorded so a Chromium
// profile can send Proxy-Connection instead (see withProxyConnection).
func (g *fieldGenerator) connectionField() {
	if !g.keepsConnectionAlive() {
		return
	}

	if g.addMissing("Connection", "keep-alive") {
		g.request.profileHop.keepAlive = true
	}
}

// keepsConnectionAlive reports whether the release asks to keep this
// request's HTTP/1.1 connection open. Safari sends no Connection field. A
// WebSocket handshake never gets one: its Connection: Upgrade belongs to
// the WebSocket library, and keep-alive in its place would break the
// upgrade.
func (g *fieldGenerator) keepsConnectionAlive() bool {
	if g.webSocket() {
		return false
	}

	switch g.entry.Family {
	case catalog.FamilyChromium, catalog.FamilyFirefox:
		return g.keepAlive && !g.request.Close

	default:
		return false
	}
}

// http2OnlyFields records the fields the release appends last on HTTP/2
// requests only, such as Firefox's te: trailers. They stay out of Header,
// which HTTP/1.1 writes; the HTTP/2 transport encodes them last.
func (g *fieldGenerator) http2OnlyFields() {
	for _, field := range g.entry.HTTP2OnlyFields(g.destination()) {
		name := CanonicalHeaderKey(field.Name)
		if g.has(name) {
			continue
		}

		hop := &g.request.profileHop
		hop.http2Fields = append(hop.http2Fields, fingerprint.Field{
			Name:  name,
			Value: field.Value,
		})
	}
}
