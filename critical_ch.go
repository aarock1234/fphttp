package http

import "slices"

// needsHintRestart reports whether the Client should restart the top-level
// page load whose hop sent sent and received resp: resp's Critical-CH names
// a client hint that the origin now asks for, that the hop did not carry,
// and that the request would now carry. accepted is the list that resp's
// Accept-CH just stored, and caller is the request the Transport was given
// for the hop. Only a top-level page load reaches here, so an iframe or
// frame load never asks for a restart.
//
// A restart sends the chain's first request again, so it is asked for only
// when that request is a GET or HEAD whose body, if any, GetBody can
// replay. The Client limits how often one call restarts (see
// hintRestarts).
func (t *Transport) needsHintRestart(
	resp *Response,
	sent *Request,
	caller *Request,
	accepted []string,
) bool {
	missing := missingCriticalHints(resp, sent, accepted)
	if len(missing) == 0 {
		return false
	}

	if !replayableFirstRequest(caller.redirectChain()[0]) {
		return false
	}

	// Preparing the hop again, now that the store holds the new hints,
	// shows which hints it would carry under every rule that decides
	// whether a hint is sent, such as permission and suppression.
	candidate, err := t.prepareRequest(caller)
	if err != nil {
		return false
	}

	for _, field := range missing {
		if candidate.Header.Get(field) != "" {
			return true
		}
	}

	return false
}

// missingCriticalHints returns the canonical field names of the client
// hints that resp's Critical-CH names, that the origin asks for (accepted),
// and that sent did not carry. A malformed Critical-CH names none.
func missingCriticalHints(resp *Response, sent *Request, accepted []string) []string {
	critical, _ := parseClientHintList(resp.Header.Values("Critical-Ch"))

	var missing []string

	for _, name := range critical {
		field := CanonicalHeaderKey(name)
		if slices.Contains(accepted, name) && sent.Header.Get(field) == "" {
			missing = append(missing, field)
		}
	}

	return missing
}

// replayableFirstRequest reports whether a Client can send first, the first
// request of a redirect chain, again: a GET or HEAD without a body, or with
// a body that GetBody can replay.
func replayableFirstRequest(first *Request) bool {
	switch first.Method {
	case "", MethodGet, MethodHead:
	default:
		return false
	}

	return first.Body == nil || first.Body == NoBody || first.GetBody != nil
}
