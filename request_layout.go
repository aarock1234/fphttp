package http

import (
	"maps"

	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// http1Layout returns the request to write on an HTTP/1.1 connection and
// the field order that Request.write uses when the request has no
// HeaderOrder of its own.
//
// Without a profile both are the caller's, as upstream. With a profile the
// fallback order is the snapshot's HeaderOrder, and the casing map is the
// snapshot's H1HeaderCase overlaid with the request's, the request winning
// per field. In that case the returned request is a shallow copy carrying
// the merged map; the caller's request is never modified.
func (t *Transport) http1Layout(request *Request) (*Request, []string) {
	snapshot := t.profileState.snapshot
	if snapshot == nil {
		return request, nil
	}

	if len(snapshot.H1HeaderCase) == 0 {
		return request, snapshot.HeaderOrder
	}

	layered := new(*request)
	layered.H1HeaderCase = mergeHeaderCase(snapshot.H1HeaderCase, request.H1HeaderCase)

	return layered, snapshot.HeaderOrder
}

// mergeHeaderCase returns the profile's casing map overlaid with the
// request's, keyed by canonical field name. When the request has no casing
// of its own, the profile map, already canonical, is returned as it is.
// Neither input is modified.
func mergeHeaderCase(profile, request map[string]string) map[string]string {
	if len(request) == 0 {
		return profile
	}

	merged := make(map[string]string, len(profile)+len(request))
	maps.Copy(merged, profile)

	for name, spelling := range request {
		merged[CanonicalHeaderKey(name)] = spelling
	}

	return merged
}

// withCanonicalHeaderCase returns r when its H1HeaderCase keys are
// canonical, and otherwise a shallow copy whose map has canonical keys.
// HTTP/1.1 writers look spellings up by canonical name, but H1HeaderCase
// accepts keys in any case. r is never modified.
func (r *Request) withCanonicalHeaderCase() *Request {
	if hasCanonicalKeys(r.H1HeaderCase) {
		return r
	}

	canonical := new(*r)
	canonical.H1HeaderCase = canonicalHeaderCase(r.H1HeaderCase)

	return canonical
}

// canonicalHeaderCase returns names keyed by canonical field name. It
// returns names itself when every key is already canonical and never
// modifies it.
func canonicalHeaderCase(names map[string]string) map[string]string {
	if hasCanonicalKeys(names) {
		return names
	}

	canonical := make(map[string]string, len(names))
	for name, spelling := range names {
		canonical[CanonicalHeaderKey(name)] = spelling
	}

	return canonical
}

// hasCanonicalKeys reports whether every key of names is a canonical field
// name.
func hasCanonicalKeys(names map[string]string) bool {
	for name := range names {
		if CanonicalHeaderKey(name) != name {
			return false
		}
	}

	return true
}

// resolveOrder prefers the request's order over the transport's fallback.
// A non-nil request order wins even when empty. The result is nil, which
// selects Go's order, whenever the chosen order is empty.
func resolveOrder(request, fallback []string) []string {
	return fingerprint.ResolveOrder(request, fallback)
}
