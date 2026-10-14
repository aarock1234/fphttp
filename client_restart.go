package http

// maxHintRestarts is the most times one Client call restarts its redirect
// chain for client hints. Each origin restarts a call at most once, as in
// Chromium; this bound also stops a chain that crosses many origins.
const maxHintRestarts = 10

// hintRestarts restarts the redirect chain of one Client call when a
// Transport with a Profile marks a response (see Response.restartForHints):
// the response's Critical-CH names client hints that its origin now asks
// for and that the request lacked. The restarted chain begins again with
// the call's first request and shares the call's deadline.
//
// The Client and the Transport communicate only through the response, so a
// RoundTripper that wraps the Transport and returns its responses keeps
// restarts working.
type hintRestarts struct {
	// first is the request passed to Client.Do.
	first *Request

	// jarHeader is first's Header as the caller set it, copied before the
	// first send when the Client has a Jar, which adds its cookies to
	// first's own Header, so rebuilding from that would send them twice.
	// It is nil without a Jar: first's Header then stays as the caller set
	// it, and is copied only when a restart happens.
	jarHeader Header

	// origins holds the origins whose responses restarted the chain.
	origins map[string]bool

	// count is how many times the chain restarted.
	count int
}

// newHintRestarts returns the restart state of a Client call whose first
// request is first. It must run before the first send, because with a Jar
// it copies first's Header (see hintRestarts.jarHeader). Without a Jar it
// copies nothing, and the state is a value the call keeps on its stack, so
// a call that never restarts allocates nothing for it.
func (c *Client) newHintRestarts(first *Request) hintRestarts {
	restarts := hintRestarts{
		first: first,
	}

	if c.Jar != nil {
		restarts.jarHeader = first.Header.Clone()
	}

	return restarts
}

// restart returns the first request of a restarted redirect chain when
// resp, the response to hop, asks for a restart that the limits allow, or
// nil to carry on with resp. When it returns a request, it has closed
// resp's body and hop's body, as following a redirect does. A first
// request whose body cannot be replayed is not restarted.
func (r *hintRestarts) restart(hop *Request, resp *Response) *Request {
	if !r.allows(hop, resp) {
		return nil
	}

	first, replayed := r.firstRequest()
	if !replayed {
		return nil
	}

	r.record(hop)

	resp.closeBody()
	hop.closeBody()

	return first
}

// allows reports whether resp asks for a restart and the limits allow it:
// the origin of hop, which received resp, has not restarted the call yet,
// and the call has restarted fewer than maxHintRestarts times.
func (r *hintRestarts) allows(hop *Request, resp *Response) bool {
	if !resp.restartForHints || r.count >= maxHintRestarts {
		return false
	}

	origin := requestOrigin(hop.URL)

	return origin != "" && !r.origins[origin]
}

// record counts a restart caused by the response to hop.
func (r *hintRestarts) record(hop *Request) {
	if r.origins == nil {
		r.origins = make(map[string]bool)
	}

	r.origins[requestOrigin(hop.URL)] = true
	r.count++
}

// firstRequest returns a new first request for the restarted chain: a
// clone of the request passed to Client.Do with the Header it had before
// the first send and, when it has a body, a new body from GetBody. It
// reports false when the body cannot be replayed, because GetBody is nil
// or fails; the Client then carries on with the response it has, which is
// a complete answer to the request.
func (r *hintRestarts) firstRequest() (*Request, bool) {
	first := r.first.Clone(r.first.Context())
	first.Header = r.callerHeader()

	if r.first.Body == nil || r.first.Body == NoBody {
		return first, true
	}

	if r.first.GetBody == nil {
		return nil, false
	}

	body, err := r.first.GetBody()
	if err != nil {
		return nil, false
	}

	first.Body = body

	return first, true
}

// callerHeader returns a copy of the first request's Header as the caller
// set it: the copy taken before the first send when the Client has a Jar,
// and the request's own Header, which nothing has changed, otherwise.
func (r *hintRestarts) callerHeader() Header {
	if r.jarHeader != nil {
		return r.jarHeader.Clone()
	}

	return r.first.Header.Clone()
}
