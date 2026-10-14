package main

import (
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

// versionPrefix returns the first count components of version.
func versionPrefix(version string, count int) string {
	parts := strings.Split(version, ".")
	if len(parts) > count {
		parts = parts[:count]
	}

	return strings.Join(parts, ".")
}
