package http

import "fmt"

// Destination is the kind of resource a request loads, as sent in
// Sec-Fetch-Dest. The zero value is a top-level page load.
//
// A Transport with a Profile derives a request's browser fields from its
// Destination and fails a request whose Destination is not one of the
// constants below. Without a Profile, only a Client reads it, to decide
// whether to apply its Jar (see Request.Destination).
type Destination string

// Request destinations. Each is the Sec-Fetch-Dest value a browser sends for
// that kind of load.
const (
	// DestinationDocument is a top-level page load, as when the user types a
	// URL or follows a link. It is the same as the zero Destination.
	DestinationDocument Destination = "document"

	// DestinationIframe is a document loaded into an iframe element, a
	// nested navigation.
	DestinationIframe Destination = "iframe"

	// DestinationFrame is a document loaded into a frame element, a nested
	// navigation.
	DestinationFrame Destination = "frame"

	// DestinationEmpty is a request made by fetch() or XMLHttpRequest.
	DestinationEmpty Destination = "empty"

	// DestinationImage is an image, such as an img element's source or a CSS
	// background.
	DestinationImage Destination = "image"

	// DestinationScript is a classic or module script.
	DestinationScript Destination = "script"

	// DestinationStyle is a style sheet.
	DestinationStyle Destination = "style"

	// DestinationFont is a web font.
	DestinationFont Destination = "font"

	// DestinationAudio is the media of an audio element.
	DestinationAudio Destination = "audio"

	// DestinationVideo is the media of a video element.
	DestinationVideo Destination = "video"

	// DestinationTrack is a text track, such as WebVTT captions.
	DestinationTrack Destination = "track"

	// DestinationManifest is a web app manifest.
	DestinationManifest Destination = "manifest"

	// DestinationObject is the resource of an object element, which browsers
	// load into a content frame as a nested navigation.
	DestinationObject Destination = "object"

	// DestinationEmbed is the resource of an embed element, which browsers
	// load into a content frame as a nested navigation.
	DestinationEmbed Destination = "embed"

	// DestinationWorker is a dedicated worker script.
	DestinationWorker Destination = "worker"

	// DestinationSharedWorker is a shared worker script.
	DestinationSharedWorker Destination = "sharedworker"

	// DestinationServiceWorker is a service worker script.
	DestinationServiceWorker Destination = "serviceworker"

	// DestinationReport is a report sent by the Reporting API, such as a
	// Content Security Policy violation report.
	DestinationReport Destination = "report"

	// DestinationXSLT is an XSLT style sheet.
	DestinationXSLT Destination = "xslt"

	// DestinationWebSocket is a WebSocket opening handshake: an HTTP/1.1
	// request carrying Upgrade: websocket, or an HTTP/2 extended CONNECT
	// whose :protocol is websocket. A Transport with a Profile gives a
	// handshake this Destination when Destination is zero, so a WebSocket
	// library that sends its handshake through a Client gets it without
	// setting it. Like Go's, the Transport rejects a :protocol header
	// field, so handshakes currently travel over HTTP/1.1, on a connection
	// of their own when the request also carries Connection: Upgrade.
	//
	// Unlike the other constants, it is not a Sec-Fetch-Dest value.
	// Chromium sends no Sec-Fetch-* fields on a handshake, and Firefox sends
	// Sec-Fetch-Mode: websocket with Sec-Fetch-Dest "websocket" through
	// release 115 and "empty" from 116. The handshake carries the browser's
	// Origin, cache-bypassing Pragma and Cache-Control, Accept-Encoding,
	// Accept-Language, and cookies, and no navigation fields. Initiator is
	// the page that opens the socket; when it is nil, the handshake comes
	// from a page on the target's own origin.
	//
	// fphttp never generates Upgrade, Connection, or the Sec-WebSocket-*
	// fields, which belong to the WebSocket library; the browser's header
	// order still places them. Safari's handshake is not verified, so a
	// Safari profile adds only Origin.
	DestinationWebSocket Destination = "websocket"
)

// fetchMode is a Fetch request mode, as sent in Sec-Fetch-Mode.
type fetchMode string

// Request modes a Destination implies.
const (
	// modeNavigate loads a document into a frame.
	modeNavigate fetchMode = "navigate"

	// modeCORS may cross origins under the CORS protocol.
	modeCORS fetchMode = "cors"

	// modeNoCORS may cross origins and yields an opaque response.
	modeNoCORS fetchMode = "no-cors"

	// modeSameOrigin fails unless the request stays on its initiator's
	// origin.
	modeSameOrigin fetchMode = "same-origin"

	// modeWebSocket opens a WebSocket.
	modeWebSocket fetchMode = "websocket"
)

// valid reports whether d is the zero Destination or one of the Destination
// constants.
func (d Destination) valid() bool {
	switch d {
	case "",
		DestinationDocument,
		DestinationIframe,
		DestinationFrame,
		DestinationEmpty,
		DestinationImage,
		DestinationScript,
		DestinationStyle,
		DestinationFont,
		DestinationAudio,
		DestinationVideo,
		DestinationTrack,
		DestinationManifest,
		DestinationObject,
		DestinationEmbed,
		DestinationWorker,
		DestinationSharedWorker,
		DestinationServiceWorker,
		DestinationReport,
		DestinationXSLT,
		DestinationWebSocket:
		return true
	default:
		return false
	}
}

// validate returns an error naming d when it is not a valid Destination.
func (d Destination) validate() error {
	if d.valid() {
		return nil
	}

	return fmt.Errorf("fphttp: unknown request destination %q", string(d))
}

// navigation reports whether d loads a document into a frame: a top-level
// page load, an iframe or frame load, or the content frame of an object or
// embed element. Navigations use mode navigate, include credentials, and
// are ordered by Profile.HeaderOrder.
func (d Destination) navigation() bool {
	switch d {
	case "",
		DestinationDocument,
		DestinationIframe,
		DestinationFrame,
		DestinationObject,
		DestinationEmbed:
		return true
	default:
		return false
	}
}

// topLevel reports whether d is a top-level page load: the zero Destination
// or DestinationDocument. Unlike an iframe or frame load, it replaces the
// whole page, and it counts as user-activated by default.
func (d Destination) topLevel() bool {
	return d == "" || d == DestinationDocument
}

// media reports whether d loads the media of an audio or video element.
func (d Destination) media() bool {
	return d == DestinationAudio || d == DestinationVideo
}

// secFetchDest returns the Sec-Fetch-Dest value of d: "document" for the
// zero Destination and d itself otherwise.
func (d Destination) secFetchDest() string {
	if d == "" {
		return string(DestinationDocument)
	}

	return string(d)
}

// mode returns the request mode a browser uses for d, as sent in
// Sec-Fetch-Mode. Navigations use navigate; fetch(), fonts, and manifests
// use cors; worker scripts use same-origin; WebSocket handshakes use
// websocket; every other subresource uses no-cors. d must be valid.
func (d Destination) mode() fetchMode {
	if d.navigation() {
		return modeNavigate
	}

	switch d {
	case DestinationEmpty, DestinationFont, DestinationManifest:
		return modeCORS
	case DestinationWorker, DestinationSharedWorker, DestinationServiceWorker:
		return modeSameOrigin
	case DestinationWebSocket:
		return modeWebSocket
	default:
		return modeNoCORS
	}
}

// credentials returns the credentials mode a browser uses for d.
// fetch(), fonts, reports, and worker scripts use same-origin; manifests
// omit credentials; navigations, WebSocket handshakes, and every other
// subresource use include. An invalid Destination omits credentials, so a
// Client never applies its Jar to a request whose kind it cannot tell.
//
// Fetch opens a WebSocket with credentials mode include, and Chromium
// (URLRequestHttpJob::AddCookieHeaderAndStart) and Firefox send the
// cookies of the socket's URL whatever the page's origin.
//
// Chromium and Firefox fetch a manifest without credentials unless its link
// is crossorigin="use-credentials", which a Destination cannot express.
// Chromium sends violation reports with same-origin credentials
// (PingLoader::SendViolationReport); Firefox sends them anonymously, so a
// Firefox report to its own origin carries cookies it would not.
func (d Destination) credentials() CredentialsMode {
	if !d.valid() {
		return CredentialsOmit
	}

	switch d {
	case DestinationManifest:
		return CredentialsOmit
	case DestinationEmpty,
		DestinationFont,
		DestinationReport,
		DestinationWorker,
		DestinationSharedWorker,
		DestinationServiceWorker:
		return CredentialsSameOrigin
	default:
		return CredentialsInclude
	}
}
