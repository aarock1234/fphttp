package http

import (
	"maps"
	"slices"
	"strings"
)

// fieldValuesFold returns the values of the field name in h and whether the
// field is present, matching keys ignoring case. Header methods match
// canonical keys only, but a Header filled by assignment may use any
// spelling. The canonical key wins when several keys match.
func fieldValuesFold(h Header, name string) ([]string, bool) {
	if values, ok := h[CanonicalHeaderKey(name)]; ok {
		return values, true
	}

	for key, values := range h {
		if strings.EqualFold(key, name) {
			return values, true
		}
	}

	return nil, false
}

// firstFieldFold returns the first value of the field name in h under any
// spelling, or "" when the field is absent or empty.
func firstFieldFold(h Header, name string) string {
	values, _ := fieldValuesFold(h, name)
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

// fieldSuppressedFold reports whether h holds the field name, under any
// spelling, with a present but empty value (see emptyFieldValues). With a
// Profile such a value suppresses the field, and a Client applies no Jar
// cookies over an empty Cookie field.
func fieldSuppressedFold(h Header, name string) bool {
	values, present := fieldValuesFold(h, name)

	return present && emptyFieldValues(values)
}

// emptyFieldValues reports whether values is a present but empty field
// value: a nil or empty slice, or a single empty string.
func emptyFieldValues(values []string) bool {
	return len(values) == 0 || len(values) == 1 && values[0] == ""
}

// canonicalizeFieldFold moves the values of every key of h that spells name
// with different case to name's canonical key, after any values already
// there. Header methods and the HTTP/1.1 writers find a field by its
// canonical key only, so a variant spelling would otherwise go unnoticed.
// A variant that is present but empty leaves the canonical key present.
// h is modified in place, so it must belong to the caller.
func canonicalizeFieldFold(h Header, name string) {
	key := CanonicalHeaderKey(name)

	for spelling, values := range h {
		if spelling == key || !strings.EqualFold(spelling, key) {
			continue
		}

		h[key] = append(h[key], values...)
		delete(h, spelling)
	}
}

// headerKeySpellings maps the canonical name of every non-canonical key in
// h to that key, the spelling the caller chose for the field. When one
// field has several non-canonical spellings, the first in sorted order
// wins. Canonical keys, and invalid field names, which CanonicalHeaderKey
// leaves unchanged, are skipped. h is not modified.
func headerKeySpellings(h Header) map[string]string {
	spellings := make(map[string]string)

	for _, key := range slices.Sorted(maps.Keys(h)) {
		canonical := CanonicalHeaderKey(key)
		if key == canonical {
			continue
		}

		if _, recorded := spellings[canonical]; !recorded {
			spellings[canonical] = key
		}
	}

	return spellings
}

// wireHeaderName returns the HTTP/1.1 spelling of the field name: its entry
// in names, which is keyed by canonical name, or name itself when names has
// none.
func wireHeaderName(name string, names map[string]string) string {
	if spelling := names[CanonicalHeaderKey(name)]; spelling != "" {
		return spelling
	}

	return name
}
