package http

import (
	"maps"
	"slices"
	"strings"
)

// newPreparedRequest returns the private clone of req that a Transport with
// the profile snapshot prepares for one hop: a shallow copy whose Header is
// a deep copy with canonical keys (see normalizeHeader), and whose
// H1HeaderCase also records the caller's non-canonical key spellings (see
// preparedHeaderCase). A Referer that a Client generated for a redirect hop
// is left out when the profile generates fields, which replace it (see
// headerToPrepare). req is never modified.
//
// Header methods, the HTTP/1.1 writers, and the Client find fields by their
// canonical keys, so a key such as "user-agent" would otherwise be missed,
// for example sent next to Go's default User-Agent.
func newPreparedRequest(req *Request, snapshot *Profile) *Request {
	header, spellings := normalizeHeader(headerToPrepare(req, snapshot))

	prepared := new(*req)
	prepared.Header = header
	prepared.H1HeaderCase = preparedHeaderCase(req.H1HeaderCase, spellings)
	prepared.profileHop = profileHop{
		prepared: true,
	}

	return prepared
}

// headerToPrepare returns the fields a prepared request starts from:
// req.Header without the canonical Referer key when the Client generated
// it (see Request.clientReferer) and snapshot generates fields, whose
// Referer follows the browser's referrer policy instead (see
// fieldGenerator.refererField). A profile that generates no fields keeps
// the Client's Referer, the previous hop's URL, as upstream does. Another
// spelling of Referer is the caller's and always stays. req.Header is not
// modified.
func headerToPrepare(req *Request, snapshot *Profile) Header {
	if !req.clientReferer || !snapshot.generatesFields() {
		return req.Header
	}

	header := maps.Clone(req.Header)
	delete(header, "Referer")

	return header
}

// normalizeHeader returns a deep copy of h whose keys are all canonical,
// together with the spelling of every field that h keys non-canonically
// (see headerKeySpellings). Keys that spell one field with different case
// are merged into its canonical key (see mergeFieldSpellings). Present but
// empty values stay present. A nil h returns a nil Header, so a profile's
// nil Header stays nil. h is not modified.
func normalizeHeader(h Header) (Header, map[string]string) {
	normalized := h.Clone()
	spellings := headerKeySpellings(normalized)

	for name := range spellings {
		mergeFieldSpellings(normalized, name)
	}

	return normalized, spellings
}

// mergeFieldSpellings moves every key of h that spells the canonical field
// name to name itself. The values merge in this order: the canonical key's,
// then the other spellings' in sorted key order. Empty values are dropped;
// when no value is left the field stays present but empty, so it still
// suppresses the field. Cookie values are joined with "; " into one value,
// the form a single Cookie field takes. h is modified in place.
func mergeFieldSpellings(h Header, name string) {
	var values []string

	for _, key := range fieldSpellings(h, name) {
		values = append(values, nonEmptyValues(h[key])...)
		delete(h, key)
	}

	if name == "Cookie" && len(values) > 1 {
		values = []string{strings.Join(values, "; ")}
	}

	h[name] = values
}

// fieldSpellings returns the keys of h that spell the canonical field name:
// name itself first when present, then the other spellings in sorted order.
func fieldSpellings(h Header, name string) []string {
	var spellings []string

	for _, key := range slices.Sorted(maps.Keys(h)) {
		if key != name && strings.EqualFold(key, name) {
			spellings = append(spellings, key)
		}
	}

	if _, present := h[name]; present {
		spellings = slices.Insert(spellings, 0, name)
	}

	return spellings
}

// nonEmptyValues returns the non-empty strings of values, in order.
func nonEmptyValues(values []string) []string {
	var kept []string

	for _, value := range values {
		if value != "" {
			kept = append(kept, value)
		}
	}

	return kept
}

// preparedHeaderCase returns the HTTP/1.1 casing of a prepared request: the
// request's own H1HeaderCase keyed by canonical name, plus the caller's key
// spellings for the fields it does not list. The HTTP/1.1 writer overlays
// the result on the profile's casing, which gives the precedence
// Request.H1HeaderCase, the caller's spelling, Profile.H1HeaderCase, then
// the canonical form. requestCase is returned as it is when there are no
// spellings; neither input is modified.
func preparedHeaderCase(requestCase, spellings map[string]string) map[string]string {
	if len(spellings) == 0 {
		return requestCase
	}

	merged := make(map[string]string, len(requestCase)+len(spellings))
	for name, spelling := range requestCase {
		merged[CanonicalHeaderKey(name)] = spelling
	}

	for name, spelling := range spellings {
		if _, listed := merged[name]; !listed {
			merged[name] = spelling
		}
	}

	return merged
}
