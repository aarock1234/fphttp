package main

import (
	"strconv"
	"strings"
)

// versionMajor returns the first component of a dotted version, or zero
// when it is not numeric.
func versionMajor(version string) int {
	major, _, _ := strings.Cut(version, ".")
	value, _ := strconv.Atoi(major)

	return value
}
