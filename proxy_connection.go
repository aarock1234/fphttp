package http

import "github.com/aarock1234/fphttp/v2/internal/catalog"

// withProxyConnection returns request as a Chromium release writes it to an
// HTTP proxy that forwards it to a plain-http URL: Chromium sends
// Proxy-Connection: keep-alive there instead of Connection: keep-alive
// (HttpNetworkTransaction::BuildRequestHeaders). toProxy reports such a
// connection; the request URL is then always plain http.
//
// Only a Connection field the Transport generated is replaced, never one the
// caller set, and a Proxy-Connection field the request already has is kept.
// The result is a shallow copy with its own Header, because the round trip
// that sent the request still reads its Header while the connection writes
// it. In every other case request itself is returned.
func (t *Transport) withProxyConnection(request *Request, toProxy bool) *Request {
	if !toProxy || !request.profileHop.keepAlive {
		return request
	}

	if t.profileState.snapshot.family() != catalog.FamilyChromium {
		return request
	}

	header := request.Header.Clone()
	header.Del("Connection")

	if !header.has("Proxy-Connection") {
		header.Set("Proxy-Connection", "keep-alive")
	}

	proxied := new(*request)
	proxied.Header = header

	return proxied
}
