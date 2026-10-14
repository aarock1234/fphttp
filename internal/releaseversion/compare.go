// Package releaseversion compares dotted numeric browser versions for the
// catalog tools. It imports only the standard library.
package releaseversion

import (
	"cmp"
	"strconv"
	"strings"
)

// Compare compares two dotted numeric versions component by component,
// treating a missing or non-numeric component as zero.
func Compare(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	for index := range max(len(aParts), len(bParts)) {
		order := cmp.Compare(component(aParts, index), component(bParts, index))
		if order != 0 {
			return order
		}
	}

	return 0
}

// component returns the numeric component at index. It returns zero when
// the version has fewer components or the component is not a decimal
// number, so such a component orders before every positive one.
func component(parts []string, index int) int {
	if index >= len(parts) {
		return 0
	}

	value, err := strconv.Atoi(parts[index])
	if err != nil {
		return 0
	}

	return value
}
