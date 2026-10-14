package http

import (
	"maps"
	"slices"

	"github.com/aarock1234/fphttp/v2/internal/catalog"
)

// chromiumConnectOrder is the field order of a Chromium CONNECT request.
// ProxyClientSocket::BuildTunnelRequest sets Host, Proxy-Connection, and
// User-Agent, then merges the proxy's Proxy-Authorization. Fields the
// caller adds follow in sorted order.
var chromiumConnectOrder = []string{
	"Host",
	"Proxy-Connection",
	"User-Agent",
	"Proxy-Authorization",
}

// applyProfileToConnect makes a CONNECT request look like the one the
// profile's browser sends to open a tunnel. Without a profile it does
// nothing, keeping Go's behavior.
//
// When the caller's proxy headers have no User-Agent, the request carries
// the profile's User-Agent, or none when the profile's Header has none: a
// Transport with a profile never sends Go's default User-Agent. A Chromium
// release writes the fields in Chromium's order and adds Proxy-Connection:
// keep-alive, except when the profile's Header is nil, which disables every
// generated field. Fields the caller set are kept.
//
// The request's Header is replaced by a copy before any change, because it
// may be the Transport's ProxyConnectHeader, and the request gets its own
// order and casing because OnProxyConnectResponse receives it.
//
// The caller's User-Agent and Proxy-Connection move to their canonical keys
// first. The HTTP/1.1 writers look User-Agent up by canonical key only, so
// a key such as "user-agent" would otherwise be written next to Go's
// default User-Agent, or replaced by it. The caller's spelling of every
// non-canonical key still reaches the wire through the request's casing
// (see connectHeaderCase).
func (t *Transport) applyProfileToConnect(connectReq *Request) {
	snapshot := t.profileState.snapshot
	if snapshot == nil {
		return
	}

	header := connectReq.Header.Clone()
	headerCase := connectHeaderCase(snapshot.H1HeaderCase, header)

	canonicalizeFieldFold(header, "User-Agent")
	canonicalizeFieldFold(header, "Proxy-Connection")

	addTunnelFields(header, snapshot)

	if snapshot.family() == catalog.FamilyChromium {
		connectReq.HeaderOrder = slices.Clone(chromiumConnectOrder)
	}

	connectReq.Header = header
	connectReq.H1HeaderCase = headerCase
}

// prepareTunnelRequest prepares a CONNECT request that the caller sends
// through Transport.RoundTrip or a ClientConn, as the profile's browser
// opens a tunnel (see applyProfileToConnect). It adds only the tunnel
// fields (see addTunnelFields), and a Chromium release writes them in
// Chromium's order unless the request has a HeaderOrder of its own.
//
// Profile.Header and the generated browser fields belong to the requests
// sent through the tunnel, never to the CONNECT request itself. prepared is
// the Transport's private clone, whose Header has canonical keys.
func prepareTunnelRequest(prepared *Request, snapshot *Profile) {
	addTunnelFields(prepared.Header, snapshot)

	if prepared.HeaderOrder != nil {
		return
	}

	if snapshot.family() == catalog.FamilyChromium {
		prepared.HeaderOrder = chromiumConnectOrder
	}
}

// addTunnelFields adds to header, whose User-Agent and Proxy-Connection
// keys are canonical, the fields of a browser's CONNECT request that header
// does not set:
//
//   - User-Agent from the profile's Header, or an empty one, which sends no
//     User-Agent, when the profile's Header has none, so a Transport with a
//     profile never sends Go's default.
//   - For a Chromium release, Proxy-Connection: keep-alive, unless the
//     profile's Header is nil, which disables every generated field.
func addTunnelFields(header Header, snapshot *Profile) {
	if !header.has("User-Agent") {
		header.Set("User-Agent", firstFieldFold(snapshot.Header, "User-Agent"))
	}

	if snapshot.family() != catalog.FamilyChromium || snapshot.Header == nil {
		return
	}

	if !header.has("Proxy-Connection") {
		header.Set("Proxy-Connection", "keep-alive")
	}
}

// connectHeaderCase returns the HTTP/1.1 casing of a CONNECT request: the
// profile's casing overlaid with the non-canonical key spellings in header,
// which outrank it as a request's own spellings do. The spellings must be
// recorded before any key is canonicalized, because the ordered HTTP/1.1
// writer canonicalizes every key and would otherwise lose them. The result
// never aliases profile, and neither input is modified.
func connectHeaderCase(profile map[string]string, header Header) map[string]string {
	spellings := headerKeySpellings(header)
	if len(spellings) == 0 {
		return maps.Clone(profile)
	}

	headerCase := make(map[string]string, len(profile)+len(spellings))
	maps.Copy(headerCase, profile)
	maps.Copy(headerCase, spellings)

	return headerCase
}
