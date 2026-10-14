package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/aarock1234/fphttp/v2/internal/catalog"
)

// Chromium source files the derivation reads, relative to the repository
// root.
const (
	chromiumFeaturesPath        = "net/base/features.cc"
	chromiumSocketPath          = "net/socket/ssl_client_socket_impl.cc"
	chromiumSSLConfigPath       = "net/ssl/ssl_config_service.cc"
	chromiumSSLConfigHeaderPath = "net/ssl/ssl_config_service.h"
	chromiumSSLDefaultsPath     = "net/ssl/ssl_config_service_defaults.cc"
	chromiumSessionPath         = "net/http/http_network_session.cc"
	chromiumSessionHeaderPath   = "net/http/http_network_session.h"
	chromiumSpdySessionPath     = "net/spdy/spdy_session.cc"
	chromiumSpdyUtilsPath       = "net/spdy/spdy_http_utils.cc"
	chromiumRootStorePath       = "net/data/ssl/chrome_root_store/root_store.textproto"
)

// chromiumSourcePaths lists the files every Chromium derivation reads.
var chromiumSourcePaths = []string{
	chromiumFeaturesPath,
	chromiumSocketPath,
	chromiumSSLConfigPath,
	chromiumSSLConfigHeaderPath,
	chromiumSessionPath,
	chromiumSessionHeaderPath,
	chromiumSpdySessionPath,
	chromiumSpdyUtilsPath,
}

// verifyPrefsPattern matches the signature algorithms the socket offers.
var verifyPrefsPattern = regexp.MustCompile(`static const uint16_t kVerifyPrefs\[\]\s*=\s*\{([^}]+)\}`)

// chromiumFeatures is the wire a Chromium build sends on one platform, as
// derived from its source.
type chromiumFeatures struct {
	hello                catalog.ChromiumHello
	ech                  bool
	shuffle              bool
	newALPS              bool
	mldsa                bool
	signatureGREASE      bool
	priorityHeader       bool
	maxConcurrentStreams uint32
	http2                chromiumHTTP2

	// trustAnchors reports that the Trust Anchor IDs extension is enabled;
	// trustAnchorIDs then holds the bundled root store's IDs.
	trustAnchors   bool
	trustAnchorIDs [][]byte
}

// keyAgreement is what the source says about post-quantum key shares.
type keyAgreement struct {
	// enabled is the PostQuantumKyber feature, or the code path Chromium
	// takes once the feature is gone.
	enabled bool

	// preferMLKEM is the UseMLKEM feature, which chooses X25519MLKEM768
	// over X25519Kyber768Draft00 where both are listed.
	preferMLKEM bool

	mlkemListed bool
	kyberListed bool
}

// chromiumRevision returns the Chromium source at a release tag, such as
// "152.0.7977.85".
func chromiumRevision(tag string) sourceRevision {
	return sourceRevision{
		name: "chromium " + tag,
		mirrors: []string{
			"https://raw.githubusercontent.com/chromium/chromium/" + tag + "/",
		},
	}
}

// chromiumSource is the Chromium source of one build.
type chromiumSource struct {
	revision sourceRevision
	files    sourceFiles
}

// fetchChromiumSource reads the files every Chromium derivation needs at
// tag, and ssl_config_service_defaults.cc as well when the socket takes its
// ECH mode from the config service.
func fetchChromiumSource(ctx context.Context, sources *fetcher, tag string) (chromiumSource, error) {
	revision := chromiumRevision(tag)

	files, err := sources.fetchFiles(ctx, revision, chromiumSourcePaths)
	if err != nil {
		return chromiumSource{}, err
	}

	if strings.Contains(files[chromiumSocketPath], "EchMode::kOpportunistic") {
		defaults, err := sources.fetchFile(ctx, revision, chromiumSSLDefaultsPath)
		if err != nil {
			return chromiumSource{}, err
		}

		files[chromiumSSLDefaultsPath] = defaults
	}

	source := chromiumSource{
		revision: revision,
		files:    files,
	}

	return source, nil
}

// verifyChromium derives Chrome's wire for a target's major and compares it
// with every Chrome and Edge release of that major.
func verifyChromium(ctx context.Context, sources *fetcher, t target) []finding {
	source, err := fetchChromiumSource(ctx, sources, t.representative.Version)
	if err != nil {
		return []finding{t.derivationFinding(err)}
	}

	return checkChromiumWires(ctx, sources, t, source, nil)
}

// checkChromiumWires derives the wire of source on each platform of t,
// applying overrides, and compares it with the catalog. The bundled root
// store is fetched once, and only when Trust Anchor IDs are enabled.
func checkChromiumWires(
	ctx context.Context,
	sources *fetcher,
	t target,
	source chromiumSource,
	overrides featureOverrides,
) []finding {
	var anchors [][]byte

	derive := func(platform catalog.Platform) (chromiumFeatures, error) {
		features, err := deriveChromium(source.files, platform, overrides)
		if err != nil || !features.trustAnchors {
			return features, err
		}

		if anchors == nil {
			anchors, err = fetchTrustAnchorIDs(ctx, sources, source.revision)
			if err != nil {
				return chromiumFeatures{}, err
			}
		}

		features.trustAnchorIDs = anchors

		return features, nil
	}

	return checkWires(t, derive, compareChromium)
}

// deriveChromium derives the compiled-default wire of a Chromium build on
// platform from its source files.
func deriveChromium(
	files sourceFiles,
	platform catalog.Platform,
	overrides featureOverrides,
) (chromiumFeatures, error) {
	if err := checkChromiumStructure(files); err != nil {
		return chromiumFeatures{}, err
	}

	socket := files[chromiumSocketPath]
	flags := &featureReader{
		source:    files[chromiumFeaturesPath],
		platform:  platform,
		overrides: overrides,
	}

	features := chromiumFeatures{
		shuffle:         flags.enabled("PermuteTLSExtensions", permutesByDefault(socket)),
		ech:             flags.enabled("EncryptedClientHello", echByDefault(files)),
		newALPS:         flags.enabled("UseNewAlpsCodepointHttp2", false),
		mldsa:           flags.enabled("TlsMldsaSignatures", verifyPrefsListMLDSA(socket)),
		signatureGREASE: flags.enabled("TlsGreaseSigalgs", false),
		priorityHeader:  flags.enabled("PriorityHeader", priorityFieldByDefault(files[chromiumSpdyUtilsPath])),
		trustAnchors:    flags.enabled("TLSTrustAnchorIDs", false) && flags.enabled("NonMtcTrustAnchorIDs", false),
	}

	agreement := deriveKeyAgreement(files, flags)

	if flags.err != nil {
		return chromiumFeatures{}, flags.err
	}

	hello, err := chromiumHelloOf(agreement, features.ech)
	if err != nil {
		return chromiumFeatures{}, err
	}

	http2, err := deriveChromiumHTTP2(files)
	if err != nil {
		return chromiumFeatures{}, err
	}

	features.hello = hello
	features.http2 = http2
	features.maxConcurrentStreams = http2.maxConcurrentStreams

	return features, nil
}

// deriveKeyAgreement reads the post-quantum key agreement settings.
//
// The group moved between files: 124 to 137 list it in the socket behind
// the PostQuantumKyber and UseMLKEM features; 138 to 141 list
// X25519MLKEM768 in the socket's kGroups behind the
// post_quantum_key_agreement_enabled config field, with both features gone;
// 142 on list it in ssl_config_service.cc's default groups.
func deriveKeyAgreement(files sourceFiles, flags *featureReader) keyAgreement {
	socket := files[chromiumSocketPath]

	mlkemListed := strings.Contains(socket, "SSL_GROUP_X25519_MLKEM768") ||
		strings.Contains(files[chromiumSSLConfigPath], "SSL_GROUP_X25519_MLKEM768")

	kyberListed := strings.Contains(socket, "X25519Kyber768") ||
		strings.Contains(socket, "X25519_KYBER768")

	return keyAgreement{
		enabled:     flags.enabled("PostQuantumKyber", postQuantumByDefault(files, mlkemListed)),
		preferMLKEM: flags.enabled("UseMLKEM", mlkemListed),
		mlkemListed: mlkemListed,
		kyberListed: kyberListed,
	}
}

// postQuantumByDefault reports whether a build without the PostQuantumKyber
// feature offers X25519MLKEM768: it does whenever it lists the group, unless
// the socket guards the group with post_quantum_key_agreement_enabled and
// the config field defaults to false.
func postQuantumByDefault(files sourceFiles, mlkemListed bool) bool {
	if !mlkemListed {
		return false
	}

	if !strings.Contains(files[chromiumSocketPath], "post_quantum_key_agreement_enabled") {
		return true
	}

	return strings.Contains(files[chromiumSSLConfigHeaderPath], "bool post_quantum_key_agreement_enabled = true;")
}

// permutesByDefault reports whether a build without the
// PermuteTLSExtensions feature still shuffles the ClientHello extensions.
func permutesByDefault(socket string) bool {
	return strings.Contains(socket, "SSL_set_permute_extensions(ssl_.get(), 1)")
}

// echByDefault reports whether a build without the EncryptedClientHello
// feature sends ECH GREASE: the socket must enable GREASE, and either the
// config's ech_enabled field defaults to true or, from 152 on, the default
// ECH mode is opportunistic, the mode that enables GREASE.
func echByDefault(files sourceFiles) bool {
	socket := files[chromiumSocketPath]
	if !strings.Contains(socket, "SSL_set_enable_ech_grease(ssl_.get(), 1)") {
		return false
	}

	if strings.Contains(files[chromiumSSLConfigHeaderPath], "bool ech_enabled = true;") {
		return true
	}

	return strings.Contains(socket, "case EchMode::kOpportunistic:") &&
		strings.Contains(files[chromiumSSLDefaultsPath], "return EchMode::kOpportunistic;")
}

// verifyPrefsListMLDSA reports whether the socket's signature algorithms
// list ML-DSA-44, ML-DSA-65, and ML-DSA-87 unconditionally, as they do from
// 153 on, when the TlsMldsaSignatures feature is gone.
func verifyPrefsListMLDSA(socket string) bool {
	match := verifyPrefsPattern.FindStringSubmatch(socket)
	if match == nil {
		return false
	}

	preferences := match[1]

	return strings.Contains(preferences, "SSL_SIGN_ML_DSA_44") &&
		strings.Contains(preferences, "SSL_SIGN_ML_DSA_65") &&
		strings.Contains(preferences, "SSL_SIGN_ML_DSA_87")
}

// priorityFieldByDefault reports whether a build without the PriorityHeader
// feature still sends the extensible Priority field on HTTP/2.
func priorityFieldByDefault(spdyUtils string) bool {
	return strings.Contains(spdyUtils, "SerializePriorityFieldValue") &&
		!strings.Contains(spdyUtils, "kPriorityHeader")
}

// chromiumHelloOf returns the ClientHello preset that the key agreement and
// ECH settings select.
func chromiumHelloOf(agreement keyAgreement, ech bool) (catalog.ChromiumHello, error) {
	switch {
	case agreement.enabled && agreement.preferMLKEM && agreement.mlkemListed:
		return catalog.ChromiumHelloMLKEM, nil

	case agreement.enabled && agreement.kyberListed:
		return catalog.ChromiumHelloKyber, nil

	case agreement.enabled:
		return 0, errors.New("post-quantum key agreement is enabled without a recognized group")

	case ech:
		return catalog.ChromiumHelloECH, nil

	default:
		return catalog.ChromiumHelloClassical, nil
	}
}

// checkChromiumStructure fails when the TLS and HTTP/2 setup no longer has
// the shape the derivation and the catalog's ClientHello presets assume.
func checkChromiumStructure(files sourceFiles) error {
	required := []struct {
		path string
		form string
	}{
		{
			path: chromiumSocketPath,
			form: "SSL_set_strict_cipher_list",
		},
		{
			path: chromiumSpdySessionPath,
			form: "SendInitialData",
		},
	}

	for _, requirement := range required {
		if !strings.Contains(files[requirement.path], requirement.form) {
			return fmt.Errorf("unrecognized source: %s lacks %s", requirement.path, requirement.form)
		}
	}

	return nil
}

// helloName names a Chromium hello preset in findings.
func helloName(hello catalog.ChromiumHello) string {
	switch hello {
	case catalog.ChromiumHelloClassical:
		return "classical"
	case catalog.ChromiumHelloECH:
		return "ech"
	case catalog.ChromiumHelloKyber:
		return "kyber"
	case catalog.ChromiumHelloMLKEM:
		return "mlkem"
	default:
		return fmt.Sprintf("unknown(%d)", hello)
	}
}
