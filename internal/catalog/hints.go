package catalog

// ClientHints holds the User-Agent client hints of a Chromium release as
// structured field values (RFC 8941), ready to send as field values.
//
// Brands, Mobile, and Platform are the low-entropy hints, always set. The
// other hints are sent only when a server asks for them. Such a field is
// empty when the release never sends that hint, or when its value depends
// on the device and no default has been verified, as for Arch on Windows.
// An empty structured string is the two characters `""` and is sent.
//
// Brave sends only some high-entropy hints, by version: none before
// 1.51.107, Model and PlatformVersion before 1.69, and Arch, Bitness,
// FullVersionList, Model, PlatformVersion, and WoW64 from 1.69. It never
// sends FullVersion or FormFactors.
type ClientHints struct {
	// Brands is Sec-CH-UA: a GREASE brand, Chromium, and the product brand
	// with their major versions, in Chromium's seeded order, such as
	// `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`.
	// The product brand is Google Chrome, Microsoft Edge, or Brave.
	Brands string

	// Mobile is Sec-CH-UA-Mobile: ?1 on Android and ?0 elsewhere.
	Mobile string

	// Platform is Sec-CH-UA-Platform: `"Windows"`, `"macOS"`, `"Linux"`, or
	// `"Android"`.
	Platform string

	// FullVersion is Sec-CH-UA-Full-Version: the full product build, such as
	// `"152.0.7977.85"`. Edge reports its own build.
	FullVersion string

	// Arch is Sec-CH-UA-Arch: `""` on Android, and empty on desktop
	// platforms, where it depends on the processor.
	Arch string

	// PlatformVersion is Sec-CH-UA-Platform-Version: `""` on Linux, and
	// empty elsewhere, where it depends on the operating system release.
	PlatformVersion string

	// Model is Sec-CH-UA-Model: `""` on desktop platforms. On Android it
	// names the device, so it is empty, except for Brave from 1.78, which
	// sends `""`.
	Model string

	// Bitness is Sec-CH-UA-Bitness: `""` on Android, and empty on desktop
	// platforms, where it depends on the processor.
	Bitness string

	// WoW64 is Sec-CH-UA-WoW64: ?0, because every cataloged build is a
	// native 64-bit build, as its User-Agent reports.
	WoW64 string

	// FullVersionList is Sec-CH-UA-Full-Version-List: the Brands list with
	// full versions. Brave reports every brand as "<major>.0.0.0". It is
	// empty for Edge, whose Chromium build has no official source.
	FullVersionList string

	// FormFactors is Sec-CH-UA-Form-Factors: `"Desktop"`, or `"Mobile"` on
	// Android, from Chromium 123.
	FormFactors string
}

// hintSet is a set of high-entropy client hints a release sends when asked.
type hintSet uint16

// High-entropy client hints.
const (
	hintFullVersion hintSet = 1 << iota
	hintArch
	hintPlatformVersion
	hintModel
	hintBitness
	hintWoW64
	hintFullVersionList
	hintFormFactors
)

// hintsChromium is every high-entropy hint except Form-Factors, which
// Chromium added later.
const hintsChromium = hintFullVersion |
	hintArch |
	hintPlatformVersion |
	hintModel |
	hintBitness |
	hintWoW64 |
	hintFullVersionList

// Releases where the set of high-entropy hints changes.
const (
	// chromiumFormFactorsMajor is the first Chromium major that sends
	// Sec-CH-UA-Form-Factors.
	chromiumFormFactorsMajor = 123

	// braveModelRelease is the first Brave build that sends Model and
	// Platform-Version (Chromium 113).
	braveModelRelease = "1.51.107"

	// braveHighEntropyRelease is the first Brave line that also sends Arch,
	// Bitness, Full-Version-List, and WoW64 (Chromium 128).
	braveHighEntropyRelease = "1.69"

	// braveEmptyModelRelease is the first Brave line that reports an empty
	// Model on Android.
	braveEmptyModelRelease = "1.78"
)

// has reports whether the set contains hint.
func (s hintSet) has(hint hintSet) bool {
	return s&hint != 0
}

// ClientHints returns the client hints of a Chromium release, or nil for
// other browsers. The caller owns the result.
func (e Entry) ClientHints() *ClientHints {
	platform := hintPlatform(e.Platform)
	if e.Family != FamilyChromium || platform == "" {
		return nil
	}

	hints := &ClientHints{
		Brands:   e.brands(),
		Mobile:   sfBoolean(e.Platform == Android),
		Platform: sfString(platform),
	}

	supported := e.highEntropyHints()
	e.setVersionHints(hints, supported)
	e.setDeviceHints(hints, supported)

	return hints
}

// highEntropyHints returns the high-entropy hints the release sends when
// asked.
func (e Entry) highEntropyHints() hintSet {
	if e.Browser == Brave {
		return e.braveHighEntropyHints()
	}

	if e.chromiumMajor() >= chromiumFormFactorsMajor {
		return hintsChromium | hintFormFactors
	}

	return hintsChromium
}

// braveHighEntropyHints returns the high-entropy hints a Brave release
// enables in its client hint allow list.
func (e Entry) braveHighEntropyHints() hintSet {
	switch {
	case versionAtLeast(e.Version, braveHighEntropyRelease):
		return hintArch | hintBitness | hintFullVersionList | hintModel | hintPlatformVersion | hintWoW64
	case versionAtLeast(e.Version, braveModelRelease):
		return hintModel | hintPlatformVersion
	default:
		return 0
	}
}

// setVersionHints fills the hints that describe the browser build.
func (e Entry) setVersionHints(hints *ClientHints, supported hintSet) {
	if supported.has(hintFullVersion) {
		hints.FullVersion = sfString(e.Version)
	}

	if supported.has(hintFullVersionList) {
		hints.FullVersionList = e.fullVersionList()
	}

	if supported.has(hintFormFactors) {
		hints.FormFactors = sfString(formFactor(e.Platform))
	}
}

// setDeviceHints fills the hints that describe the device, where the value
// does not vary between devices of the platform.
func (e Entry) setDeviceHints(hints *ClientHints, supported hintSet) {
	empty := sfString("")

	if supported.has(hintArch) && e.Platform == Android {
		hints.Arch = empty
	}

	if supported.has(hintBitness) && e.Platform == Android {
		hints.Bitness = empty
	}

	if supported.has(hintPlatformVersion) && e.Platform == Linux {
		hints.PlatformVersion = empty
	}

	if supported.has(hintModel) && e.emptyModel() {
		hints.Model = empty
	}

	if supported.has(hintWoW64) {
		hints.WoW64 = sfBoolean(false)
	}
}

// emptyModel reports whether the release reports an empty Model: always on
// desktop platforms, and on Android only for Brave from 1.78.
func (e Entry) emptyModel() bool {
	if e.Platform != Android {
		return true
	}

	return e.Browser == Brave && versionAtLeast(e.Version, braveEmptyModelRelease)
}

// hintPlatform returns the Sec-CH-UA-Platform name of a platform, or "" for
// a platform without a Chromium profile.
func hintPlatform(platform Platform) string {
	switch platform {
	case Windows:
		return "Windows"
	case Mac:
		return "macOS"
	case Linux:
		return "Linux"
	case Android:
		return "Android"
	default:
		return ""
	}
}

// formFactor returns the Sec-CH-UA-Form-Factors member of a platform.
func formFactor(platform Platform) string {
	if platform == Android {
		return "Mobile"
	}

	return "Desktop"
}
