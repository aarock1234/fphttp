package http

import (
	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// profileHop records how a Transport with a Profile prepared its private
// clone of a request for one hop. The clone, and every shallow copy the
// Transport makes of it, carries it to the HTTP/1.1 and HTTP/2 writers and
// back to the round trip that sent it.
type profileHop struct {
	// prepared reports that the request is the Transport's private clone,
	// which must never be handed back to the caller.
	prepared bool

	// http2Fields holds the fields sent after every other field on
	// HTTP/2 only, such as Firefox's te: trailers. HTTP/1.1 never writes
	// them, because they are not part of the request's Header.
	http2Fields []fingerprint.Field

	// keepAlive reports that the Transport generated Connection:
	// keep-alive. A Chromium profile sends it as Proxy-Connection on a
	// plain-http request to a proxy (see withProxyConnection).
	keepAlive bool

	// acceptEncoding reports that the Transport added Accept-Encoding, from
	// Profile.Header or by generating it, so the response body is encoded
	// as the profile asked, not as the caller asked, and the Transport
	// decodes it (see decodeResponse).
	acceptEncoding bool
}

// prepareRequest returns the request that a Transport sends for one http or
// https hop. Without a profile it returns req itself, so the Transport
// behaves exactly as upstream.
//
// With a profile it returns a private clone of req, and req and its Header
// are never modified. The clone is built in these steps:
//
//  1. Header keys are normalized to canonical form, and the caller's
//     non-canonical spellings become HTTP/1.1 casing (newPreparedRequest).
//  2. Profile.Header fills the fields the request does not set
//     (layerProfileHeader).
//  3. The per-destination header order replaces a nil HeaderOrder
//     (selectHeaderOrder).
//  4. A profile with a Header and a release identity generates the browser
//     fields the request still lacks (fieldGenerator.generate).
//  5. Present but empty fields, which suppress a field, are removed, and a
//     missing User-Agent is suppressed so Go's default is never sent
//     (removeSuppressedFields).
//
// A CONNECT request, which opens a tunnel, replaces steps 2 to 4 with the
// few fields the browser sends on its own tunnel request
// (prepareTunnelRequest), so it never looks like a page load.
//
// The Transport then validates the clone's fields as upstream does. An
// unknown Destination fails the request, because every generated field
// depends on it.
func (t *Transport) prepareRequest(req *Request) (*Request, error) {
	snapshot := t.profileState.snapshot
	if snapshot == nil {
		return req, nil
	}

	if err := req.Destination.validate(); err != nil {
		return nil, err
	}

	prepared := newPreparedRequest(req, snapshot)

	if prepared.Method == MethodConnect {
		prepareTunnelRequest(prepared, snapshot)
	} else {
		t.addBrowserFields(prepared, snapshot)
	}

	removeSuppressedFields(prepared)

	return prepared, nil
}

// addBrowserFields runs steps 2 to 4 of prepareRequest on its private
// clone: it layers the profile's Header, selects the header order for the
// request's Destination, and generates the browser fields the request
// still lacks.
func (t *Transport) addBrowserFields(prepared *Request, snapshot *Profile) {
	chain := prepared.redirectChain()

	layerProfileHeader(prepared, snapshot.Header, chain)
	selectHeaderOrder(prepared, snapshot)

	if snapshot.generatesFields() {
		t.newFieldGenerator(prepared, chain).generate()
	}
}

// generatesFields reports whether a Transport generates browser fields for
// p: p has a Header, which nil disables, and the release identity whose
// values the fields carry.
func (p *Profile) generatesFields() bool {
	return p.Header != nil && p.hasIdentity()
}

// restoreCallerRequest points resp.Request back at the caller's request when
// it is the private clone that prepareRequest made. An alternate round
// tripper, such as the HTTP/2 transport reusing a cached connection, sets
// resp.Request to the request it was given; the main round-trip loop always
// sets the caller's request, as upstream does. Either way the clone's
// generated fields never reach the caller.
func restoreCallerRequest(resp *Response, caller *Request) {
	if resp == nil || resp.Request == nil || !resp.Request.profileHop.prepared {
		return
	}

	resp.Request = caller
}
