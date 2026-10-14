package catalog

// Major returns the first component of the product version: 152 for Chrome
// "152.0.7977.85", 1 for Brave "1.90.128", and 27 for Safari "27.0". It
// returns zero for an Entry that Lookup did not return.
func (e Entry) Major() int {
	parts, ok := parseVersionParts(e.Version)
	if !ok {
		return 0
	}

	return parts.major()
}

// chromiumMajor returns the Chromium major of a Chromium-family release.
// Chrome and Brave record their Chromium build in Engine. Edge records none,
// but its Chromium major equals its own major.
func (e Entry) chromiumMajor() int {
	if major := entryEngineMajor(e); major != 0 {
		return major
	}

	return e.Major()
}
