package browser

import (
	"errors"
	"strconv"
	"strings"

	http "github.com/aarock1234/fphttp"
)

type identityBrand struct {
	name    string
	version string
}

// Chromium's GenerateBrandVersionList and GetGreasedUserAgentBrandVersion
// use the engine's major version as a stable seed. This is not TLS GREASE.
func chromiumBrands(p *Profile, full bool) (string, error) {
	engine := p.descriptor.EngineVersion
	if full && !completeEngineVersion(engine) {
		return "", errors.New("browser: full client hints require an exact four-component engine build")
	}
	if engine == "" {
		if p.descriptor.Browser != http.BrowserChrome || full {
			return "", errors.New("browser: client hints require a recorded engine version")
		}
		engine = p.descriptor.Version
	}
	major, err := identityMajor(engine)
	if err != nil {
		return "", err
	}
	punctuation := []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	greaseVersions := []string{"8", "99", "24"}
	greaseName := "Not" + punctuation[major%len(punctuation)] + "A" + punctuation[(major+1)%len(punctuation)] + "Brand"
	greaseVersion := greaseVersions[major%len(greaseVersions)]
	chromiumVersion := strconv.Itoa(major)
	productVersion := chromiumVersion
	productName := "Google Chrome"
	switch p.descriptor.Browser {
	case http.BrowserEdge:
		productName = "Microsoft Edge"
		productMajor, err := identityMajor(p.descriptor.Version)
		if err != nil {
			return "", err
		}
		productVersion = strconv.Itoa(productMajor)
	case http.BrowserBrave:
		productName = "Brave"
	}
	if full {
		greaseVersion += ".0.0.0"
		chromiumVersion = engine
		productVersion = p.descriptor.Version
		if p.descriptor.Browser == http.BrowserBrave {
			// Brave's embedder-support patch reduces both real brand versions.
			chromiumVersion = strconv.Itoa(major) + ".0.0.0"
			productVersion = chromiumVersion
		}
	}
	brands := []identityBrand{
		{
			name:    greaseName,
			version: greaseVersion,
		},
		{
			name:    "Chromium",
			version: chromiumVersion,
		},
		{
			name:    productName,
			version: productVersion,
		},
	}
	orders := [6][3]int{
		{0, 1, 2},
		{0, 2, 1},
		{1, 0, 2},
		{1, 2, 0},
		{2, 0, 1},
		{2, 1, 0},
	}
	order := orders[major%len(orders)]
	serialized := make([]string, len(brands))
	for i, brand := range brands {
		name, err := structuredString(brand.name)
		if err != nil {
			return "", err
		}
		version, err := structuredString(brand.version)
		if err != nil {
			return "", err
		}
		serialized[order[i]] = name + ";v=" + version
	}

	return strings.Join(serialized, ", "), nil
}

func completeEngineVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}

	return true
}

func structuredString(value string) (string, error) {
	var encoded strings.Builder
	encoded.Grow(len(value) + 2)
	encoded.WriteByte('"')
	for i := range len(value) {
		character := value[i]
		if character < 0x20 || character > 0x7e {
			return "", errors.New("browser: client-hint strings require printable ASCII")
		}
		if character == '"' || character == '\\' {
			encoded.WriteByte('\\')
		}
		encoded.WriteByte(character)
	}
	encoded.WriteByte('"')

	return encoded.String(), nil
}

func structuredBoolean(value bool) string {
	if value {
		return "?1"
	}

	return "?0"
}
