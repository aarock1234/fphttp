package browser

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	http "github.com/aarock1234/fphttp"
)

// IdentityHeaders returns independently owned basic identity headers for an
// HTTPS request. Request preparation also applies destination, permission, and
// range gates. It does not include negotiated high-entropy hints.
// A profile that requires a captured User-Agent or device metadata returns an
// empty map; supply that metadata or header through Client request options.
func (p *Profile) IdentityHeaders() http.Header {
	headers, err := identityHeaders(p, nil, true)
	if err != nil {
		return make(http.Header)
	}

	return headers
}

func identityHeaders(p *Profile, device *DeviceMetadata, advancedEncoding bool) (http.Header, error) {
	if p == nil {
		return nil, errors.New("browser: identity requires a profile")
	}

	userAgent, err := profileUserAgent(p, device)
	if err != nil {
		return nil, err
	}
	headers := make(http.Header)
	headers.Set("User-Agent", userAgent)
	headers.Set("Accept-Encoding", profileEncodings(p, advancedEncoding))
	hints, err := basicClientHintValues(p, device)
	if err != nil {
		return nil, err
	}
	for name, values := range hints {
		headers[name] = values
	}

	return headers, nil
}

func basicClientHintValues(p *Profile, device *DeviceMetadata) (http.Header, error) {
	headers := make(http.Header)
	if !chromiumClientHints(p) {
		return headers, nil
	}

	brands, err := chromiumBrands(p, false)
	if err != nil {
		return nil, err
	}
	platform, err := structuredString(hintPlatform(p.descriptor.Platform))
	if err != nil {
		return nil, err
	}
	headers.Set("Sec-Ch-Ua", brands)
	headers.Set("Sec-Ch-Ua-Mobile", structuredBoolean(profileMobile(p, device)))
	headers.Set("Sec-Ch-Ua-Platform", platform)

	return headers, nil
}

func profileUserAgent(p *Profile, device *DeviceMetadata) (string, error) {
	descriptor := p.descriptor
	major, err := identityMajor(descriptor.Version)
	if err != nil {
		return "", err
	}
	if descriptor.Platform == http.PlatformIOS || descriptor.Platform == http.PlatformIPadOS {
		return appleUserAgent(p, device)
	}

	switch descriptor.Browser {
	case http.BrowserChrome, http.BrowserEdge, http.BrowserBrave:
		return chromiumUserAgent(p, device)
	case http.BrowserFirefox:
		system := ""
		switch descriptor.Platform {
		case http.PlatformWindows:
			system = "Windows NT 10.0; Win64; x64"
		case http.PlatformMac:
			system = "Macintosh; Intel Mac OS X 10.15"
		case http.PlatformLinux:
			system = "X11; Linux x86_64"
		case http.PlatformAndroid:
			if device != nil && device.Mobile != nil && !*device.Mobile {
				return "", errors.New("browser: non-mobile Android Firefox identity requires a captured User-Agent override")
			}
			osVersion, err := userAgentOSVersion(p, device)
			if err != nil {
				return "", err
			}
			system = "Android " + strings.ReplaceAll(osVersion, "_", ".") + "; Mobile"
		default:
			return "", fmt.Errorf("browser: Firefox identity is unavailable on %s", descriptor.Platform)
		}
		version := strconv.Itoa(major) + ".0"
		gecko := "20100101"
		if descriptor.Platform == http.PlatformAndroid {
			gecko = version
		}

		return fmt.Sprintf("Mozilla/5.0 (%s; rv:%s) Gecko/%s Firefox/%s", system, version, gecko, version), nil
	case http.BrowserSafari:
		if descriptor.Platform != http.PlatformMac {
			return "", fmt.Errorf("browser: Safari identity is unavailable on %s", descriptor.Platform)
		}

		return fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Safari/605.1.15", descriptor.Version), nil
	default:
		return "", fmt.Errorf("browser: identity is unavailable for %s", descriptor.Browser)
	}
}

func chromiumUserAgent(p *Profile, device *DeviceMetadata) (string, error) {
	descriptor := p.descriptor
	engine := descriptor.EngineVersion
	if engine == "" {
		if descriptor.Browser != http.BrowserChrome {
			return "", fmt.Errorf("browser: %s identity requires its Chromium engine version", descriptor.Browser)
		}
		engine = descriptor.Version
	}
	major, err := identityMajor(engine)
	if err != nil {
		return "", err
	}
	system := ""
	switch descriptor.Platform {
	case http.PlatformWindows:
		system = "Windows NT 10.0; Win64; x64"
	case http.PlatformMac:
		system = "Macintosh; Intel Mac OS X 10_15_7"
	case http.PlatformLinux:
		system = "X11; Linux x86_64"
	case http.PlatformAndroid:
		if descriptor.Browser == http.BrowserChrome && major < 110 {
			return "", errors.New("browser: unreduced Android Chrome identity requires a captured User-Agent override")
		}
		if descriptor.Browser == http.BrowserEdge && major < 140 {
			return "", errors.New("browser: unreduced Android Edge identity requires a captured User-Agent override")
		}
		system = "Linux; Android 10; K"
	default:
		return "", fmt.Errorf("browser: Chromium identity is unavailable on %s", descriptor.Platform)
	}

	engineVersion := strconv.Itoa(major) + ".0.0.0"
	productVersion := engineVersion
	if descriptor.Browser == http.BrowserEdge {
		productMajor, err := identityMajor(descriptor.Version)
		if err != nil {
			return "", err
		}
		productVersion = strconv.Itoa(productMajor) + ".0.0.0"
		if productMajor < 119 {
			if !completeEngineVersion(engine) {
				return "", errors.New("browser: unreduced Edge identity requires a complete engine build or captured User-Agent override")
			}
			engineVersion = engine
			productVersion = descriptor.Version
		}
	}
	product := "Safari/537.36"
	if profileMobile(p, device) {
		product = "Mobile " + product
	}
	userAgent := fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s %s", system, engineVersion, product)
	if descriptor.Browser == http.BrowserEdge {
		token := "Edg/"
		if descriptor.Platform == http.PlatformAndroid {
			token = "EdgA/"
		}
		userAgent += " " + token + productVersion
	}

	return userAgent, nil
}

func appleUserAgent(p *Profile, device *DeviceMetadata) (string, error) {
	descriptor := p.descriptor
	if descriptor.Platform == http.PlatformIPadOS && descriptor.Browser == http.BrowserSafari {
		return fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Safari/605.1.15", descriptor.Version), nil
	}
	osVersion, err := userAgentOSVersion(p, device)
	if err != nil {
		return "", err
	}
	deviceName := "iPhone; CPU iPhone OS "
	if descriptor.Platform == http.PlatformIPadOS {
		deviceName = "iPad; CPU OS "
	}
	prefix := "Mozilla/5.0 (" + deviceName + osVersion + " like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
	switch descriptor.Browser {
	case http.BrowserSafari:
		return prefix + "Version/" + descriptor.Version + " Mobile/15E148 Safari/604.1", nil
	case http.BrowserChrome:
		return prefix + "CriOS/" + descriptor.Version + " Mobile/15E148 Safari/604.1", nil
	case http.BrowserEdge:
		return prefix + "EdgiOS/" + descriptor.Version + " Mobile/15E148 Safari/605.1.15", nil
	case http.BrowserFirefox:
		return prefix + "FxiOS/" + descriptor.Version + " Mobile/15E148 Safari/605.1.15", nil
	default:
		return "", errors.New("browser: branded iOS identity requires a captured User-Agent override")
	}
}

func userAgentOSVersion(p *Profile, device *DeviceMetadata) (string, error) {
	version := p.descriptor.UserAgentOSVersion
	if device != nil && device.UserAgentOSVersion != "" {
		version = device.UserAgentOSVersion
	}
	if version == "" {
		return "", fmt.Errorf("browser: %s identity requires its User-Agent OS version", p.descriptor.ID)
	}
	version = strings.ReplaceAll(version, ".", "_")
	for _, part := range strings.Split(version, "_") {
		if part == "" {
			return "", errors.New("browser: invalid User-Agent OS version")
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return "", errors.New("browser: invalid User-Agent OS version")
		}
	}

	return version, nil
}

func profileEncodings(p *Profile, advanced bool) string {
	encodings := "gzip, deflate"
	if !advanced {
		return encodings
	}
	encodings += ", br"
	major, _ := identityMajor(p.descriptor.Version)
	if chromiumClientHints(p) {
		engineMajor, _ := identityMajor(p.descriptor.EngineVersion)
		if engineMajor >= 123 {
			encodings += ", zstd"
		}
	} else if p.descriptor.Browser == http.BrowserFirefox && p.descriptor.Platform != http.PlatformIOS && p.descriptor.Platform != http.PlatformIPadOS && major >= 126 {
		encodings += ", zstd"
	}

	return encodings
}

func chromiumClientHints(p *Profile) bool {
	if p == nil || p.descriptor.Platform == http.PlatformIOS || p.descriptor.Platform == http.PlatformIPadOS {
		return false
	}

	switch p.descriptor.Browser {
	case http.BrowserChrome, http.BrowserEdge, http.BrowserBrave:
		return true
	default:
		return false
	}
}

func profileMobile(p *Profile, device *DeviceMetadata) bool {
	if device != nil && device.Mobile != nil {
		return *device.Mobile
	}

	return p.descriptor.Platform == http.PlatformAndroid || p.descriptor.Platform == http.PlatformIOS
}

func hintPlatform(platform http.Platform) string {
	switch platform {
	case http.PlatformWindows:
		return "Windows"
	case http.PlatformMac:
		return "macOS"
	case http.PlatformLinux:
		return "Linux"
	case http.PlatformAndroid:
		return "Android"
	default:
		return ""
	}
}

func identityMajor(version string) (int, error) {
	major, _, _ := strings.Cut(version, ".")
	value, err := strconv.Atoi(major)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("browser: invalid identity version %q", version)
	}

	return value, nil
}

func advancedEncodingDestination(profile *Profile, destination *url.URL) bool {
	if destination == nil {
		return false
	}
	if destination.Scheme == "https" {
		return true
	}

	return chromiumClientHints(profile) && destination.Scheme == "http" && headerLocalhost(destination.Hostname())
}
