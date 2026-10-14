package main

import (
	"cmp"
	"strconv"
	"strings"
)

// compareVersions compares two dotted numeric versions component by
// component, treating a missing or non-numeric component as zero.
func compareVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	for index := range max(len(aParts), len(bParts)) {
		order := cmp.Compare(versionComponent(aParts, index), versionComponent(bParts, index))
		if order != 0 {
			return order
		}
	}

	return 0
}

// versionComponent returns the numeric component at index, or zero when the
// version has fewer components.
func versionComponent(parts []string, index int) int {
	if index >= len(parts) {
		return 0
	}

	value, _ := strconv.Atoi(parts[index])

	return value
}

// versionMajor returns the first component of a dotted version, or zero
// when it is not numeric.
func versionMajor(version string) int {
	major, _, _ := strings.Cut(version, ".")
	value, _ := strconv.Atoi(major)

	return value
}
