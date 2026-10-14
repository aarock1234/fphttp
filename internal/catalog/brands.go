package catalog

import (
	"strconv"
	"strings"
)

// Inputs of Chromium's GREASE brand (GetGreasedUserAgentBrandVersion) and
// brand permutation (ShuffleBrandList). The Chromium major seeds both, so
// every build of a major sends the same list. This GREASE is unrelated to
// TLS GREASE.
var (
	// greaseBrandCharacters fill the two gaps in "Not?A?Brand".
	greaseBrandCharacters = [...]string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}

	// greaseBrandVersions are the GREASE brand's possible major versions.
	greaseBrandVersions = [...]string{"8", "99", "24"}

	// brandOrders lists every order of the GREASE, Chromium, and product
	// brands. Each row holds the list position of those three brands in
	// turn.
	brandOrders = [...][3]int{
		{0, 1, 2},
		{0, 2, 1},
		{1, 0, 2},
		{1, 2, 0},
		{2, 0, 1},
		{2, 1, 0},
	}
)

// brand is one member of a client hint brand list.
type brand struct {
	name    string
	version string
}

// brands returns the Sec-CH-UA brand list: the GREASE brand, Chromium, and
// the product brand with their major versions.
func (e Entry) brands() string {
	major := e.chromiumMajor()

	return serializeBrands(major, [3]brand{
		greaseBrand(major),
		{
			name:    "Chromium",
			version: strconv.Itoa(major),
		},
		{
			name:    productBrandName(e.Browser),
			version: strconv.Itoa(e.productBrandMajor()),
		},
	})
}

// fullVersionList returns the Sec-CH-UA-Full-Version-List brand list with
// full versions. Brave zeroes all but the major of every brand. Chrome and
// Edge need the full Chromium build, so the list is "" when Engine does not
// hold one, as for Edge.
func (e Entry) fullVersionList() string {
	major := e.chromiumMajor()

	grease := greaseBrand(major)
	grease.version += ".0.0.0"

	if e.Browser == Brave {
		return serializeBrands(major, [3]brand{
			grease,
			{
				name:    "Chromium",
				version: reducedVersion(major),
			},
			{
				name:    productBrandName(e.Browser),
				version: reducedVersion(major),
			},
		})
	}

	if !completeBuild(e.Engine) {
		return ""
	}

	return serializeBrands(major, [3]brand{
		grease,
		{
			name:    "Chromium",
			version: e.Engine,
		},
		{
			name:    productBrandName(e.Browser),
			version: e.Version,
		},
	})
}

// greaseBrand returns the GREASE brand Chromium derives from seed.
func greaseBrand(seed int) brand {
	first := greaseBrandCharacters[seed%len(greaseBrandCharacters)]
	second := greaseBrandCharacters[(seed+1)%len(greaseBrandCharacters)]

	return brand{
		name:    "Not" + first + "A" + second + "Brand",
		version: greaseBrandVersions[seed%len(greaseBrandVersions)],
	}
}

// serializeBrands places the GREASE, Chromium, and product brands in the
// order seed selects and serializes them as a structured field list.
func serializeBrands(seed int, members [3]brand) string {
	order := brandOrders[seed%len(brandOrders)]

	var placed [3]string
	for i, member := range members {
		placed[order[i]] = sfString(member.name) + ";v=" + sfString(member.version)
	}

	return strings.Join(placed[:], ", ")
}

// productBrandName returns the brand a Chromium-family browser reports for
// itself.
func productBrandName(browser Browser) string {
	switch browser {
	case Edge:
		return "Microsoft Edge"
	case Brave:
		return "Brave"
	default:
		return "Google Chrome"
	}
}

// productBrandMajor returns the major version of the product brand: Edge's
// own major, and the Chromium major for Chrome and Brave.
func (e Entry) productBrandMajor() int {
	if e.Browser == Edge {
		return e.Major()
	}

	return e.chromiumMajor()
}
