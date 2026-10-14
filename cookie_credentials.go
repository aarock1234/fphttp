package http

// sendsJarCookies reports whether a Client adds its Jar's cookies to r
// before sending it. The request's credentials mode must allow cookies for
// its URL (see carriesCredentials).
//
// A navigation, including the zero Destination, always gets them, exactly
// as upstream, where AddCookie replaces a present but empty Cookie field.
// Any other request declines them with such a field, for example
// Header["Cookie"] = []string{""} (see declinesJarCookies). The Client
// reads only the caller's Destination, never a detected one, so a
// request with a zero Destination always behaves as upstream.
func (r *Request) sendsJarCookies() bool {
	if !r.carriesCredentials() {
		return false
	}

	if r.Destination.navigation() {
		return true
	}

	return !r.declinesJarCookies()
}

// declinesJarCookies reports whether r, or the first request of its
// redirect chain, holds a present but empty Cookie field. The decline lasts
// for the whole chain, as a browser's credentials mode does: a Client
// strips the Cookie field from a hop to another host, so the hop alone
// would no longer show it.
func (r *Request) declinesJarCookies() bool {
	if fieldSuppressedFold(r.Header, "Cookie") {
		return true
	}

	first := r.redirectChain()[0]

	return fieldSuppressedFold(first.Header, "Cookie")
}

// storesJarCookies reports whether a Client stores in its Jar the cookies
// that the response to r sets. Browsers ignore a response's cookies exactly
// when the request's credentials mode withholds them, so an empty Cookie
// field, which only declines to send cookies, does not affect storing.
func (r *Request) storesJarCookies() bool {
	return r.carriesCredentials()
}

// carriesCredentials reports whether the credentials mode that r's
// Destination (see Request.destination) implies allows cookies for r's URL:
// always for include, which WebSocket handshakes use, never
// for omit, and for same-origin only when Initiator is nil, a request the
// user started, or has the same origin as URL. A Client evaluates it for
// every redirect hop, so a fetch that is redirected to another origin stops
// carrying cookies there.
func (r *Request) carriesCredentials() bool {
	switch r.Destination.credentials() {
	case credentialsInclude:
		return true
	case credentialsSameOrigin:
		return r.Initiator == nil || sameOrigin(r.Initiator, r.URL)
	default:
		return false
	}
}
