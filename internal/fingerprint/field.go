package fingerprint

// Field is one header field name and value. Transports use it for fields
// they write in a fixed position, such as last, rather than through a
// header map, which has no order.
type Field struct {
	// Name is the field name. Writers match it against other fields
	// ignoring case.
	Name string

	// Value is the field value.
	Value string
}
