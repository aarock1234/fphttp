package main

import (
	"cmp"
	"strconv"
	"strings"
)

// numericVersion reports whether version consists only of dot-separated
// unsigned decimal components.
func numericVersion(version string) bool {
	for part := range strings.SplitSeq(version, ".") {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return false
		}

		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}

	return true
}

// compareVersions compares two dotted numeric versions component by
// component, treating a missing component as zero.
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

// versionPrefix returns the first count components of version.
func versionPrefix(version string, count int) string {
	parts := strings.Split(version, ".")
	if len(parts) > count {
		parts = parts[:count]
	}

	return strings.Join(parts, ".")
}
