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

// safariPriorityFields maps the captured destinations to their Priority
// field. Only the document and fetch() were captured; other destinations
// keep fphttp v1's behavior and send no Priority field.
var safariPriorityFields = map[fetchDestination]string{
	destinationDocument: safariDocumentPriority,
	destinationEmpty:    safariFetchPriority,
}

// safariPriority returns Safari's priority for a destination. Safari sends
// SETTINGS_NO_RFC7540_PRIORITIES, and its HEADERS frames carry no PRIORITY
// flag.
//
// The Priority field travels on HTTP/1.1 and HTTP/2. Published HTTP/1.1
// requests from Safari 18.6 on iPhone and Safari 26.2 on macOS carry the
// document's field between Accept-Language and Accept-Encoding, as on
// HTTP/2. No HTTP/1.1 fetch() was captured, so its field follows the
// document's there.
func safariPriority(destination fetchDestination) RequestPriority {
	field := safariPriorityFields[destination]

	return RequestPriority{
		Field:        field,
		FieldOnHTTP1: field != "",
	}
}
