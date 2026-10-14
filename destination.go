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

	// DestinationObject is the resource of an object element.
	DestinationObject Destination = "object"

	// DestinationEmbed is the resource of an embed element.
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
)

// credentialsMode is a Fetch credentials mode: whether a request carries
// cookies and stores the cookies its response sets.
type credentialsMode string

// Credentials modes a Destination implies.
const (
	// credentialsOmit never carries cookies.
	credentialsOmit credentialsMode = "omit"

	// credentialsSameOrigin carries cookies only to the initiator's origin.
	credentialsSameOrigin credentialsMode = "same-origin"

	// credentialsInclude always carries cookies.
	credentialsInclude credentialsMode = "include"
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
		DestinationXSLT:
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
// page load, or an iframe or frame load. Navigations use mode navigate,
// include credentials, and are ordered by Profile.HeaderOrder.
func (d Destination) navigation() bool {
	switch d {
	case "", DestinationDocument, DestinationIframe, DestinationFrame:
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
// use cors; worker scripts use same-origin; every other subresource uses
// no-cors. d must be valid.
func (d Destination) mode() fetchMode {
	if d.navigation() {
		return modeNavigate
	}

	switch d {
	case DestinationEmpty, DestinationFont, DestinationManifest:
		return modeCORS
	case DestinationWorker, DestinationSharedWorker, DestinationServiceWorker:
		return modeSameOrigin
	default:
		return modeNoCORS
	}
}

// credentials returns the credentials mode a browser uses for d.
// fetch(), fonts, manifests, and worker scripts use same-origin; navigations
// and every other subresource use include. An invalid Destination omits
// credentials, so a Client never applies its Jar to a request whose kind it
// cannot tell.
func (d Destination) credentials() credentialsMode {
	if !d.valid() {
		return credentialsOmit
	}

	switch d {
	case DestinationEmpty,
		DestinationFont,
		DestinationManifest,
		DestinationWorker,
		DestinationSharedWorker,
		DestinationServiceWorker:
		return credentialsSameOrigin
	default:
		return credentialsInclude
	}
}
