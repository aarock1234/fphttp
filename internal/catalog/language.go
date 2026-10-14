package catalog

// Default Accept-Language values of an English (United States) browser.
const (
	// chromiumAcceptLanguage is Chromium's en-US default: en-US, then en at
	// q=0.9.
	chromiumAcceptLanguage = "en-US,en;q=0.9"

	// firefoxDesktopAcceptLanguage is desktop Firefox's en-US default. Its
	// intl.accept_languages list "en-US, en" gives the second language
	// q=0.5.
	firefoxDesktopAcceptLanguage = "en-US,en;q=0.5"

	// firefoxAndroidAcceptLanguage is Firefox for Android on a device whose
	// only locale is en-US. GeckoView replaces intl.accept_languages with the
	// device locales, joined without quality values.
	firefoxAndroidAcceptLanguage = "en-US"

	// safariAcceptLanguage is Safari on an English system, captured from
	// Safari 26.0.1 and 27 on macOS and iPhone.
	safariAcceptLanguage = "en-US,en;q=0.9"
)

// AcceptLanguage returns the Accept-Language the release sends with an
// English (United States) locale. It is empty for an Entry that Lookup did
// not return.
func (e Entry) AcceptLanguage() string {
	switch e.Family {
	case FamilyChromium:
		return chromiumAcceptLanguage

	case FamilyFirefox:
		if e.Platform == Android {
			return firefoxAndroidAcceptLanguage
		}

		return firefoxDesktopAcceptLanguage

	case FamilySafari:
		return safariAcceptLanguage

	default:
		return ""
	}
}
