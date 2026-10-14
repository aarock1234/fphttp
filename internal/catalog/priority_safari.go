package catalog

// Safari Priority field values. Safari writes the default urgency 3
// explicitly.
const (
	// safariDocumentPriority is the top-level document's Priority field,
	// captured from Safari 26.0.1 on macOS and Safari 27 on macOS and
	// iPhone.
	safariDocumentPriority = "u=0, i"

	// safariFetchPriority is the Priority field of fetch(), captured from
	// Safari 27 on macOS and iPhone only. The Safari 26.0.1 capture holds
	// only a navigation, so Safari 26.0 carries this value over from 27.
	safariFetchPriority = "u=3, i"
)

// safariPriority returns Safari's priority for a destination. Safari sends
// SETTINGS_NO_RFC7540_PRIORITIES, and its HEADERS frames carry no PRIORITY
// flag.
//
// Only the document and fetch() were captured, on HTTP/2. Other
// destinations and HTTP/1.1 keep fphttp v1's behavior and send no Priority
// field.
func safariPriority(destination fetchDestination) RequestPriority {
	switch destination {
	case destinationDocument:
		return RequestPriority{Field: safariDocumentPriority}
	case destinationEmpty:
		return RequestPriority{Field: safariFetchPriority}
	default:
		return RequestPriority{}
	}
}
