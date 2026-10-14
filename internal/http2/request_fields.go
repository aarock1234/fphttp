package http2

import (
	"maps"
	"net/textproto"
	"slices"
	"strings"

	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// encodeAddedFieldNames are fields EncodeHeaders can add outside the
// request's Header map. Reserving their positions keeps added fields after
// them when they appear.
var encodeAddedFieldNames = []string{
	"Accept-Encoding",
	"Content-Length",
	"Trailer",
	"User-Agent",
}

// requestHeadersToEncode returns the fields and the order to encode for
// req: its Header plus the fields the transport adds, each only when Header
// does not have it under any spelling. The Priority field from
// H2PriorityHeader comes first, then LastFields in order. Added fields that
// headerOrder does not list follow every other field. req.Header is never
// modified; when fields are added, the result is a copy.
func requestHeadersToEncode(req *ClientRequest, headerOrder []string) (Header, []string) {
	added := addedRequestFields(req)
	if len(added) == 0 {
		return req.Header, headerOrder
	}

	headers := maps.Clone(req.Header)
	if headers == nil {
		headers = make(Header)
	}

	for _, field := range added {
		headers[field.Name] = append(headers[field.Name], field.Value)
	}

	return headers, addedFieldsOrder(headers, headerOrder, added)
}

// addedRequestFields returns the fields the transport adds to req's Header,
// under canonical names: Priority from H2PriorityHeader, then LastFields,
// skipping each field Header already has.
func addedRequestFields(req *ClientRequest) []fingerprint.Field {
	var added []fingerprint.Field

	if req.H2PriorityHeader != "" && !hasField(req.Header, "Priority") {
		added = append(added, fingerprint.Field{
			Name:  "Priority",
			Value: req.H2PriorityHeader,
		})
	}

	for _, field := range req.LastFields {
		if hasField(req.Header, field.Name) {
			continue
		}

		added = append(added, fingerprint.Field{
			Name:  textproto.CanonicalMIMEHeaderKey(field.Name),
			Value: field.Value,
		})
	}

	return added
}

// hasField reports whether headers has the field name under any spelling.
func hasField(headers Header, name string) bool {
	for key := range headers {
		if strings.EqualFold(key, name) {
			return true
		}
	}

	return false
}

// addedFieldsOrder returns the order that places the added fields last. When
// headerOrder lists every added field, it is returned as it is. Otherwise
// the result lists headerOrder, then every other field in sorted order, then
// the unlisted added fields in the order they were added.
func addedFieldsOrder(headers Header, headerOrder []string, added []fingerprint.Field) []string {
	listed := make(map[string]bool, len(headerOrder)+len(added))
	for _, name := range headerOrder {
		listed[strings.ToLower(name)] = true
	}

	var last []string
	for _, field := range added {
		key := strings.ToLower(field.Name)
		if listed[key] {
			continue
		}

		listed[key] = true
		last = append(last, field.Name)
	}

	if len(last) == 0 {
		return headerOrder
	}

	order := slices.Clone(headerOrder)
	order = append(order, unlistedFieldNames(headers, listed)...)

	return append(order, last...)
}

// unlistedFieldNames returns, in sorted order and canonical form, the
// regular fields of headers and the fields EncodeHeaders may add that
// listed does not contain. listed is keyed by lowercase name and is updated
// with every returned name.
func unlistedFieldNames(headers Header, listed map[string]bool) []string {
	var unlisted []string

	add := func(name string) {
		key := strings.ToLower(name)
		if strings.HasPrefix(name, ":") || listed[key] {
			return
		}

		listed[key] = true
		unlisted = append(unlisted, textproto.CanonicalMIMEHeaderKey(name))
	}

	for name := range headers {
		add(name)
	}

	for _, name := range encodeAddedFieldNames {
		add(name)
	}

	slices.Sort(unlisted)

	return unlisted
}
