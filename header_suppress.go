package http

// removeSuppressedFields removes from a prepared request every field whose
// value is present but empty (see emptyFieldValues). Such a value, set by
// the caller or by Profile.Header, has already kept the Transport from
// generating the field, and must not reach the wire as an empty field.
//
// User-Agent is the exception: an absent or empty User-Agent becomes the
// single empty value, which the HTTP/1.1 and HTTP/2 writers read as "send
// no User-Agent", so a Transport with a profile never sends Go's default.
// A suppressed Priority field also clears H2PriorityHeader, which an empty
// Priority field suppresses (see Request.H2PriorityHeader).
func removeSuppressedFields(request *Request) {
	for name, values := range request.Header {
		if name == "User-Agent" || !emptyFieldValues(values) {
			continue
		}

		delete(request.Header, name)

		if name == "Priority" {
			request.H2PriorityHeader = ""
		}
	}

	if emptyFieldValues(request.Header["User-Agent"]) {
		request.Header["User-Agent"] = []string{""}
	}
}
