package catalog

import "strings"

// sfString serializes value as a structured field string (RFC 8941),
// escaping quotes and backslashes. Catalog values are printable ASCII.
func sfString(value string) string {
	var encoded strings.Builder
	encoded.Grow(len(value) + 2)

	encoded.WriteByte('"')

	for i := range len(value) {
		character := value[i]
		if character == '"' || character == '\\' {
			encoded.WriteByte('\\')
		}

		encoded.WriteByte(character)
	}

	encoded.WriteByte('"')

	return encoded.String()
}

// sfBoolean serializes value as a structured field boolean: ?1 or ?0.
func sfBoolean(value bool) string {
	if value {
		return "?1"
	}

	return "?0"
}
