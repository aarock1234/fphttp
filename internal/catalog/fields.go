package catalog

// Field is one header field name and value.
type Field struct {
	// Name is the canonical field name, such as "Te".
	Name string

	// Value is the field value.
	Value string
}

// HTTP2OnlyFields returns the fields the release appends after every other
// field on HTTP/2 requests and never sends on HTTP/1.1, in wire order, for a
// request destination (see Accept). Firefox sends te: trailers on every
// HTTP/2 request; other browsers send nothing extra. It returns nil for an
// unknown destination. The caller owns the returned slice.
func (e Entry) HTTP2OnlyFields(destination string) []Field {
	if e.Family != FamilyFirefox || parseDestination(destination) == destinationUnknown {
		return nil
	}

	return []Field{
		{
			Name:  "Te",
			Value: "trailers",
		},
	}
}
