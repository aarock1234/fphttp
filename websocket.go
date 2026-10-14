package http

import (
	"net/url"
	"strings"
)

// webSocketToken is the Upgrade token and the :protocol value that open a
// WebSocket, in the lowercase form hasToken expects.
const webSocketToken = "websocket"

// protocolPseudoHeader is the Header key that carries the :protocol
// pseudo-header of an HTTP/2 extended CONNECT request (RFC 8441).
const protocolPseudoHeader = ":protocol"

// destination returns the Destination that browser fields and cookies
// follow for r: r.Destination, or DestinationWebSocket when r.Destination
// is zero and r is a WebSocket handshake (see webSocketHandshake). A
// WebSocket library sending its handshake through a Client therefore never
// looks like a top-level page load.
func (r *Request) destination() Destination {
	if r.Destination == "" && r.webSocketHandshake() {
		return DestinationWebSocket
	}

	return r.Destination
}

// webSocketHandshake reports whether r opens a WebSocket: an extended
// CONNECT request whose :protocol is websocket (RFC 8441), or any other
// request whose Upgrade field lists the websocket token (RFC 6455). Field
// names and values match ignoring case.
func (r *Request) webSocketHandshake() bool {
	if r.Method == MethodConnect {
		protocol := firstFieldFold(r.Header, protocolPseudoHeader)

		return strings.EqualFold(protocol, webSocketToken)
	}

	upgrade, _ := fieldValuesFold(r.Header, "Upgrade")
	for _, value := range upgrade {
		if hasToken(value, webSocketToken) {
			return true
		}
	}

	return false
}

// opensTunnel reports whether r is a CONNECT request that asks for a
// tunnel, as opposed to an extended CONNECT that opens a WebSocket.
func (r *Request) opensTunnel() bool {
	return r.Method == MethodConnect && !r.webSocketHandshake()
}

// webSocketInitiator returns the page that opens r's WebSocket: Initiator,
// or URL when Initiator is nil. A browser always opens a WebSocket from a
// page, so a handshake is never user-initiated; without an Initiator, fphttp
// assumes a page on the socket's own origin.
func (r *Request) webSocketInitiator() *url.URL {
	if r.Initiator != nil {
		return r.Initiator
	}

	return r.URL
}

// webSocketOrigin returns the Origin of a WebSocket handshake: the
// serialized origin of the page that opens it (see webSocketInitiator), or
// "null" when that origin is opaque. Chromium (WebSocketStreamRequestImpl)
// and Firefox (WebSocketChannel::SetupRequest) always send it, whatever the
// referrer policy, as RFC 6455 requires of browser clients.
func webSocketOrigin(request *Request) string {
	origin := requestOrigin(request.webSocketInitiator())
	if origin == "" {
		return "null"
	}

	return origin
}
