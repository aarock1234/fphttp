package catalog

import (
	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// WebSocket handshake values, from Chromium net/websockets and
// services/network/websocket.cc and Firefox WebSocketChannel.cpp,
// nsHttpChannel.cpp, and SecFetch.cpp. Sources and citations are in
// .temp-data/v2-research/websocket.md.

// cacheBypassValue is the Pragma and Cache-Control value of a request that
// bypasses the cache, as every WebSocket handshake does.
const cacheBypassValue = "no-cache"

// Sec-Fetch-Dest values of a Firefox WebSocket handshake.
const (
	// firefoxWebSocketDest115 is the value through Firefox 115, ESR 102 and
	// 115 included.
	firefoxWebSocketDest115 = "websocket"

	// firefoxWebSocketDest116 is the value from Firefox 116, ESR 128
	// included.
	firefoxWebSocketDest116 = "empty"

	// firefoxWebSocketDestEmptyMajor maps TYPE_WEBSOCKET to "empty" in
	// MapInternalContentPolicyTypeToDest.
	firefoxWebSocketDestEmptyMajor = 116
)

// webSocketCacheFields returns the fields a browser sends because it opens
// a WebSocket with the cache bypassed: Chromium's LOAD_BYPASS_CACHE
// (HttpNetworkTransaction::BuildRequestHeaders) and Firefox's
// LOAD_BYPASS_CACHE (nsHttpChannel::SetupChannelForTransaction) both send
// Pragma: no-cache and Cache-Control: no-cache. The caller owns the
// returned slice.
func webSocketCacheFields() []Field {
	return []Field{
		{
			Name:  "Pragma",
			Value: cacheBypassValue,
		},
		{
			Name:  "Cache-Control",
			Value: cacheBypassValue,
		},
	}
}

// WebSocketSecFetchDest returns the Sec-Fetch-Dest value the release sends
// on a WebSocket handshake, or "" when it sends no fetch metadata on one.
// When it returns a value, the release also sends Sec-Fetch-Mode: websocket
// and Sec-Fetch-Site, to potentially trustworthy URLs only.
//
// Chromium sends no fetch metadata on a WebSocket handshake: the network
// service adds it in URLLoader, which WebSockets do not use. Firefox sends
// "websocket" through 115 and "empty" from 116. Safari's handshake was not
// verified and gets none.
func (e Entry) WebSocketSecFetchDest() string {
	if e.Family != FamilyFirefox {
		return ""
	}

	if e.Major() >= firefoxWebSocketDestEmptyMajor {
		return firefoxWebSocketDest116
	}

	return firefoxWebSocketDest115
}

// chromiumWebSocketPriority returns Chromium's priority for a WebSocket
// handshake. WebSocketStreamRequestImpl creates it at DEFAULT_PRIORITY,
// which is LOWEST, and the HTTP/2 handshake sends no Priority field
// (CreateSpdyHeadersFromHttpRequestForWebSocket).
func chromiumWebSocketPriority() RequestPriority {
	return RequestPriority{
		HTTP2: fingerprint.Priority{
			Enabled:   true,
			Exclusive: true,
			Weight:    chromiumLowest.wireWeight(),
		},
	}
}
