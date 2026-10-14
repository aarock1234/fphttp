package http

// observeClientHints updates the Transport's client hint store from resp,
// the response to one hop, as a Chromium browser does. sent is the request
// the Transport sent for the hop and caller the request it was given. Only
// a profile that generates fields and whose release sends client hints
// keeps a store worth updating.
//
// Both rules below apply to potentially trustworthy URLs only, and to
// redirect responses as well as final ones:
//
//   - Clear-Site-Data that clears client hints (see clearsClientHints)
//     forgets what the origin of the hop URL asked for, and resp's
//     Accept-CH and Critical-CH are then ignored.
//   - Otherwise the Accept-CH of a response to a top-level page load
//     replaces what the origin asked for. A valid empty list forgets it,
//     and a malformed field changes nothing. As in Chromium, where only
//     the outermost main frame parses Accept-CH, responses to iframe,
//     frame, and subresource requests teach nothing.
//
// After learning, resp is marked when the Client should restart the
// top-level page load for the hints its Critical-CH needs (see
// needsHintRestart). The response to a CONNECT request, which opens a
// tunnel and loads no page, teaches nothing.
func (t *Transport) observeClientHints(resp *Response, sent, caller *Request) {
	state := &t.profileState
	if state.hintValues == nil || !state.snapshot.generatesFields() {
		return
	}

	if sent.Method == MethodConnect {
		return
	}

	origin := requestOrigin(sent.URL)
	if origin == "" || !potentiallyTrustworthy(sent.URL) {
		return
	}

	if clearsClientHints(resp, sent, state.snapshot.entry) {
		state.hints.forget(origin)

		return
	}

	if !sent.Destination.topLevel() {
		return
	}

	values, present := resp.Header["Accept-Ch"]
	if !present {
		return
	}

	accepted, valid := parseClientHintList(values)
	if !valid {
		return
	}

	state.hints.remember(origin, accepted)
	resp.restartForHints = t.needsHintRestart(resp, sent, caller, accepted)
}
