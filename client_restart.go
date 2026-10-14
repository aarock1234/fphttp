package http

import (
	"io"
	"slices"
)

// maxHintRestarts is the most times one Client call restarts its redirect
// chain for client hints. Each origin restarts a call at most once, as in
// Chromium; this bound also stops a chain that crosses many origins.
const maxHintRestarts = 10

// maxRestartDrain is how much of a restarted response's body is read before
// it is closed, so a small body leaves its HTTP/1.1 connection reusable. It
// matches the amount Client.do reads from a redirect response.
const maxRestartDrain = 2 << 10

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

	// cookie is the Cookie field of first's Header as the caller set it,
	// and hadCookie reports whether the field was present. A Client with a
	// Jar adds its cookies to first's own Header before sending, which is
	// the only change it makes there, so a restart rebuilds the caller's
	// Header from first's with this field restored. Request.AddCookie
	// replaces the field's slice rather than appending to it, so keeping
	// the slice keeps the caller's values without copying them.
	cookie    []string
	hadCookie bool

	// origins holds the origins whose responses restarted the chain.
	origins map[string]bool

	// count is how many times the chain restarted.
	count int
}

// newHintRestarts returns the restart state of a Client call whose first
// request is first. It must run before the first send, because it records
// first's Cookie field as the caller set it (see hintRestarts.cookie). It
// copies nothing, and the state is a value the call keeps on its stack, so
// a call that never restarts allocates nothing for it.
func (c *Client) newHintRestarts(first *Request) hintRestarts {
	cookie, hadCookie := first.Header["Cookie"]

	return hintRestarts{
		first:     first,
		cookie:    cookie,
		hadCookie: hadCookie,
	}
}

// restart returns the first request of a restarted redirect chain when
// resp, the response to hop, asks for a restart that the limits allow, or
// nil to carry on with resp. When it returns a request, it has drained and
// closed resp's body and closed hop's body, as following a redirect does. A
// first request whose body cannot be replayed is not restarted.
func (r *hintRestarts) restart(hop *Request, resp *Response) *Request {
	if !r.allows(hop, resp) {
		return nil
	}

	first, replayed := r.firstRequest()
	if !replayed {
		return nil
	}

	r.record(hop)

	drainAndClose(resp)
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
// set it: a copy of its Header with the Cookie field restored to the
// caller's, which drops the cookies a Jar added.
func (r *hintRestarts) callerHeader() Header {
	header := r.first.Header.Clone()
	if header == nil {
		return nil
	}

	if r.hadCookie {
		header["Cookie"] = slices.Clone(r.cookie)
	} else {
		delete(header, "Cookie")
	}

	return header
}

// drainAndClose closes the body of resp after reading up to maxRestartDrain
// bytes of it, as Client.do does with a redirect response, so a small body
// leaves its HTTP/1.1 connection reusable. Read errors are ignored: a
// connection that fails to drain is not reused anyway.
func drainAndClose(resp *Response) {
	if resp.Body == nil {
		return
	}

	if resp.ContentLength == -1 || resp.ContentLength <= maxRestartDrain {
		_, _ = io.CopyN(io.Discard, resp.Body, maxRestartDrain)
	}

	_ = resp.Body.Close()
}
