package catalog

import (
	"fmt"
	"strconv"
)

// Operating system tokens of the default User-Agent strings. Chromium and
// Firefox report the same Windows and Linux tokens on every supported build.
const (
	// windowsSystem is 64-bit Windows 10 or 11; both report NT 10.0.
	windowsSystem = "Windows NT 10.0; Win64; x64"

	// linuxSystem is 64-bit x86 Linux.
	linuxSystem = "X11; Linux x86_64"

	// macSystem is the macOS token Chromium and Safari freeze at 10.15.7.
	macSystem = "Macintosh; Intel Mac OS X 10_15_7"

	// firefoxMacSystem is the macOS token Firefox freezes at 10.15.
	firefoxMacSystem = "Macintosh; Intel Mac OS X 10.15"

	// chromiumAndroidSystem is the reduced Android token: Android 10 and the
	// placeholder model K for every device.
	chromiumAndroidSystem = "Linux; Android 10; K"

	// firefoxAndroidSystem reports Android 14. Firefox sends the device's
	// real Android version (any version below 10 as 10, and only the major
	// from 153), so 14 stands for a current phone; callers can change it
	// through the profile's User-Agent.
	firefoxAndroidSystem = "Android 14; Mobile"
)

const (
	// firefoxDesktopGeckoTrail is the fixed Gecko date token of desktop
	// Firefox. Firefox for Android repeats its version instead.
	firefoxDesktopGeckoTrail = "20100101"

	// safariFrozenIOSVersion is the iOS version iPhone Safari has reported
	// since iOS 26 froze it at the last release before 26.
	safariFrozenIOSVersion = "18_7"
)

// UserAgent returns the User-Agent the release sends. It is never empty for
// an Entry that Lookup or Entries returned: building the catalog panics if
// a supported release has none.
func (e Entry) UserAgent() string {
	switch e.Family {
	case FamilyChromium:
		return e.chromiumUserAgent()
	case FamilyFirefox:
		return e.firefoxUserAgent()
	case FamilySafari:
		return e.safariUserAgent()
	default:
		return ""
	}
}

// chromiumUserAgent returns the reduced Chromium User-Agent: the frozen
// platform token and the Chromium major with a zeroed minor version, plus
// Edge's own product token. Brave sends exactly Chrome's string.
func (e Entry) chromiumUserAgent() string {
	system := chromiumSystem(e.Platform)
	if system == "" {
		return ""
	}

	product := "Safari/537.36"
	if e.Platform == Android {
		product = "Mobile Safari/537.36"
	}

	userAgent := fmt.Sprintf(
		"Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s %s",
		system,
		reducedVersion(e.chromiumMajor()),
		product,
	)

	if e.Browser != Edge {
		return userAgent
	}

	return userAgent + " " + edgeToken(e.Platform) + "/" + reducedVersion(e.Major())
}

// chromiumSystem returns the reduced Chromium platform token, or "" for a
// platform Chromium has no profile on.
func chromiumSystem(platform Platform) string {
	switch platform {
	case Windows:
		return windowsSystem
	case Mac:
		return macSystem
	case Linux:
		return linuxSystem
	case Android:
		return chromiumAndroidSystem
	default:
		return ""
	}
}

// reducedVersion formats a major version the way reduced User-Agent strings
// do, such as "152.0.0.0".
func reducedVersion(major int) string {
	return strconv.Itoa(major) + ".0.0.0"
}

// edgeToken returns Edge's product token: EdgA on Android and Edg elsewhere.
func edgeToken(platform Platform) string {
	if platform == Android {
		return "EdgA"
	}

	return "Edg"
}

// firefoxUserAgent returns Firefox's User-Agent. Stable and ESR releases
// alike report "<major>.0" in both rv: and the product token.
func (e Entry) firefoxUserAgent() string {
	system := firefoxSystem(e.Platform)
	if system == "" {
		return ""
	}

	version := strconv.Itoa(e.Major()) + ".0"

	geckoTrail := firefoxDesktopGeckoTrail
	if e.Platform == Android {
		geckoTrail = version
	}

	return fmt.Sprintf(
		"Mozilla/5.0 (%s; rv:%s) Gecko/%s Firefox/%s",
		system,
		version,
		geckoTrail,
		version,
	)
}

// firefoxSystem returns Firefox's platform token, or "" for a platform
// Firefox has no profile on.
func firefoxSystem(platform Platform) string {
	switch platform {
	case Windows:
		return windowsSystem
	case Mac:
		return firefoxMacSystem
	case Linux:
		return linuxSystem
	case Android:
		return firefoxAndroidSystem
	default:
		return ""
	}
}

// safariUserAgent returns Safari's User-Agent, which carries the full
// Safari version, such as "Version/27.0".
func (e Entry) safariUserAgent() string {
	switch e.Platform {
	case Mac:
		return fmt.Sprintf(
			"Mozilla/5.0 (%s) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Safari/605.1.15",
			macSystem,
			e.Version,
		)

	case IOS:
		return fmt.Sprintf(
			"Mozilla/5.0 (iPhone; CPU iPhone OS %s like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Mobile/15E148 Safari/604.1",
			safariFrozenIOSVersion,
			e.Version,
		)

	default:
		return ""
	}
}
