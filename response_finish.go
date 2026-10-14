package http

// finishResponse completes resp, the response to one hop that a Transport
// sent for caller. sent is the request the Transport sent: caller itself
// without a Profile, in which case finishResponse does nothing, so the
// Transport behaves exactly as upstream. A nil resp, from a failed round
// trip, is left alone.
//
// With a Profile, sent is the private clone that prepareRequest made, and:
//
//  1. resp.Request is the caller's request, never the clone
//     (restoreCallerRequest).
//  2. The client hint store learns from resp, which is marked when the
//     Client should restart the top-level page load for client hints
//     (observeClientHints).
//  3. The body is decoded when the Transport added Accept-Encoding for the
//     hop, from Profile.Header or by generating it, unless
//     DisableCompression is set or the response is partial (decodeResponse).
//     A caller's own Accept-Encoding gets the body as the server sent it.
//
// Both of roundTrip's response exits call it: the alternate round tripper,
// such as HTTP/2 on a cached connection, and the main loop. So does a
// ClientConn the Transport created (see ClientConn.roundTripProfile).
func (t *Transport) finishResponse(resp *Response, sent, caller *Request) {
	if resp == nil || !sent.profileHop.prepared {
		return
	}

	restoreCallerRequest(resp, caller)
	t.observeClientHints(resp, sent, caller)

	if sent.profileHop.acceptEncoding && !t.DisableCompression {
		decodeResponse(resp)
	}
}
