package catalog

// fetchDestination is a Fetch request destination, as sent in
// Sec-Fetch-Dest, grouped the way browsers treat it. The zero value is not a
// destination.
type fetchDestination uint8

// Request destinations the value functions distinguish.
const (
	// destinationUnknown is a value no browser sends.
	destinationUnknown fetchDestination = iota

	// destinationDocument is a top-level page load: "document" or "".
	destinationDocument

	// destinationSubframe is a nested navigation: "iframe" or "frame".
	destinationSubframe

	// destinationEmpty is fetch() or XMLHttpRequest.
	destinationEmpty

	destinationImage
	destinationScript
	destinationStyle
	destinationFont
	destinationAudio
	destinationVideo
	destinationTrack
	destinationManifest
	destinationObject
	destinationEmbed
	destinationWorker
	destinationSharedWorker
	destinationServiceWorker
	destinationReport
	destinationXSLT
)

// parseDestination returns the destination a Sec-Fetch-Dest value names.
// The empty string is a top-level page load.
func parseDestination(value string) fetchDestination {
	switch value {
	case "", "document":
		return destinationDocument
	case "iframe", "frame":
		return destinationSubframe
	case "empty":
		return destinationEmpty
	case "image":
		return destinationImage
	case "script":
		return destinationScript
	case "style":
		return destinationStyle
	case "font":
		return destinationFont
	case "audio":
		return destinationAudio
	case "video":
		return destinationVideo
	case "track":
		return destinationTrack
	case "manifest":
		return destinationManifest
	case "object":
		return destinationObject
	case "embed":
		return destinationEmbed
	case "worker":
		return destinationWorker
	case "sharedworker":
		return destinationSharedWorker
	case "serviceworker":
		return destinationServiceWorker
	case "report":
		return destinationReport
	case "xslt":
		return destinationXSLT
	default:
		return destinationUnknown
	}
}

// navigation reports whether the destination loads a document into a frame.
func (d fetchDestination) navigation() bool {
	return d == destinationDocument || d == destinationSubframe
}

// chromiumNavigation reports whether Chromium loads the destination as a
// frame navigation: a document, a subframe, or the content frame of an
// object or embed element (GetDestinationFromFrameTreeNode in
// navigation_request.cc).
func (d fetchDestination) chromiumNavigation() bool {
	return d.navigation() || d == destinationObject || d == destinationEmbed
}

// media reports whether the destination is an audio or video element load.
func (d fetchDestination) media() bool {
	return d == destinationAudio || d == destinationVideo
}
