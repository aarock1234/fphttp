package http

// roundTripProfile sends req, which validateClientConnRequest accepted, on
// the connection. Without a Transport whose Profile is set, it sends req
// itself, so a ClientConn behaves exactly as upstream.
//
// With a Profile, the connection sends the private clone of req that the
// Transport prepares for one hop (see Transport.prepareRequest) and
// finishes the response as Transport.RoundTrip does (see
// Transport.finishResponse): resp.Request is req, the client hint store
// learns from the response, and the body is decoded. A request the profile
// cannot prepare fails before anything is sent; its reservation is
// released and its body closed.
func (cc *ClientConn) roundTripProfile(req *Request) (*Response, error) {
	t := cc.transport
	if t == nil || t.profileState.snapshot == nil {
		return cc.cc.RoundTrip(req)
	}

	sent, err := prepareClientConnRequest(t, req)
	if err != nil {
		cc.Release()
		req.closeBody()

		return nil, err
	}

	resp, err := cc.cc.RoundTrip(sent)
	t.finishResponse(resp, sent, req)

	return resp, err
}

// prepareClientConnRequest returns the private clone of req that t's
// Profile prepares, validated as ClientConn.RoundTrip validates the
// caller's request, because Profile.Header and the generated fields are
// part of what the connection sends.
func prepareClientConnRequest(t *Transport, req *Request) (*Request, error) {
	sent, err := t.prepareRequest(req)
	if err != nil {
		return nil, err
	}

	if err := validateClientConnRequest(sent); err != nil {
		return nil, err
	}

	return sent, nil
}
