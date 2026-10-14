package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/aarock1234/fphttp/v2/internal/catalog"
)

// Firefox source files the derivation reads, relative to the repository
// root.
const (
	firefoxPrefsPath      = "modules/libpref/init/StaticPrefList.yaml"
	firefoxSocketPath     = "security/manager/ssl/nsNSSIOLayer.cpp"
	firefoxComponentPath  = "security/manager/ssl/nsNSSComponent.cpp"
	firefoxSignaturesPath = "security/manager/ssl/EnabledSignatureSchemes.h"
	firefoxSessionPath    = "netwerk/protocol/http/Http2Session.cpp"
	geckoViewPrefsPath    = "mobile/android/app/geckoview-prefs.js"
)

// firefoxSourcePaths lists the files every Firefox derivation reads.
var firefoxSourcePaths = []string{
	firefoxPrefsPath,
	firefoxSocketPath,
	firefoxSessionPath,
}

// firefoxCipherPreferences maps the cipher suite preferences Firefox has
// turned off over time to the suites they control.
var firefoxCipherPreferences = []struct {
	name  string
	suite uint16
}{
	{
		name:  "security.ssl3.ecdhe_ecdsa_aes_128_sha",
		suite: utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	},
	{
		name:  "security.ssl3.ecdhe_ecdsa_aes_256_sha",
		suite: utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	},
}

// firefoxCompressionPreferences maps the certificate compression
// preferences to their algorithms, in the order Firefox advertises them.
var firefoxCompressionPreferences = []struct {
	name      string
	algorithm utls.CertCompressionAlgo
}{
	{
		name:      "security.tls.enable_certificate_compression_zlib",
		algorithm: utls.CertCompressionZlib,
	},
	{
		name:      "security.tls.enable_certificate_compression_brotli",
		algorithm: utls.CertCompressionBrotli,
	},
	{
		name:      "security.tls.enable_certificate_compression_zstd",
		algorithm: utls.CertCompressionZstd,
	},
}

// postQuantum names the post-quantum key share a Firefox build sends.
type postQuantum string

// Post-quantum key shares: none, the X25519Kyber768 draft, or
// X25519MLKEM768.
const (
	postQuantumNone  postQuantum = "none"
	postQuantumKyber postQuantum = "kyber"
	postQuantumMLKEM postQuantum = "mlkem"
)

// firefoxFeatures is the wire a Firefox build sends on desktop or Android,
// as derived from its preference defaults and source.
type firefoxFeatures struct {
	ech                 bool
	postQuantum         postQuantum
	sct                 bool
	ffdhe               bool
	mldsa               bool
	disabledCiphers     []uint16
	certCompression     []utls.CertCompressionAlgo
	legacyTree          bool
	noRFC7540Priorities bool

	// allowPush is network.http.http2.allow-push: a build that allows
	// server push sends neither ENABLE_PUSH nor MAX_CONCURRENT_STREAMS.
	allowPush bool

	// pushMaxConcurrent reports that a build that disallows push also sends
	// MAX_CONCURRENT_STREAMS 0.
	pushMaxConcurrent bool

	headerTableSize   uint32
	initialWindowSize uint32
	connectionFlow    uint32
}

// firefoxRevision returns the Firefox source at the release tag of version,
// such as FIREFOX_150_0_3_RELEASE or FIREFOX_128_14_0esr_RELEASE. The GitHub
// mirror lacks some release tags, such as FIREFOX_115_0_3_RELEASE, so
// Mozilla's Mercurial release repository is the fallback.
func firefoxRevision(version string, esr bool) sourceRevision {
	tag := "FIREFOX_" + strings.ReplaceAll(version, ".", "_")
	repository := "mozilla-release"

	if esr {
		tag += "esr"
		repository = fmt.Sprintf("mozilla-esr%d", versionMajor(version))
	}

	tag += "_RELEASE"

	return sourceRevision{
		name: "firefox " + tag,
		mirrors: []string{
			"https://raw.githubusercontent.com/mozilla-firefox/firefox/" + tag + "/",
			"https://hg.mozilla.org/releases/" + repository + "/raw-file/" + tag + "/",
		},
	}
}

// verifyFirefox derives the wire of a target's Firefox release and compares
// it with every release of that major on the target's platforms.
func verifyFirefox(ctx context.Context, sources *fetcher, t target) []finding {
	revision := firefoxRevision(t.representative.Version, t.key.family == familyFirefoxESR)

	paths := firefoxSourcePaths
	if t.key.android {
		paths = slices.Concat(firefoxSourcePaths, []string{geckoViewPrefsPath})
	}

	files, err := sources.fetchFiles(ctx, revision, paths)
	if err != nil {
		return []finding{t.derivationFinding(err)}
	}

	derive := func(platform catalog.Platform) (firefoxFeatures, error) {
		features, err := deriveFirefox(files, platform == catalog.Android)
		if err != nil || !features.mldsa {
			return features, err
		}

		if err := checkMLDSAPolicy(ctx, sources, revision); err != nil {
			return firefoxFeatures{}, err
		}

		return features, nil
	}

	return checkWires(t, derive, compareFirefox)
}

// deriveFirefox derives the release-build wire of a Firefox build from its
// source files.
func deriveFirefox(files sourceFiles, android bool) (firefoxFeatures, error) {
	prefs := &preferenceReader{
		static:    files[firefoxPrefsPath],
		geckoView: files[geckoViewPrefsPath],
		android:   android,
	}

	socket := files[firefoxSocketPath]

	features := firefoxFeatures{
		ech:                 prefs.number("security.tls.ech.grease_probability", 0) > 0,
		postQuantum:         derivePostQuantum(prefs, socket),
		sct:                 prefs.number("security.pki.certificate_transparency.mode", 0) != 0,
		ffdhe:               deriveFFDHE(prefs, socket),
		mldsa:               prefs.boolean("security.tls.enable_mldsa", false),
		disabledCiphers:     deriveDisabledCiphers(prefs),
		certCompression:     deriveCertCompression(prefs),
		legacyTree:          prefs.boolean("network.http.http2.enabled.deps", false),
		noRFC7540Priorities: prefs.boolean("network.http.http2.send_NO_RFC7540_PRI", false),
		allowPush:           prefs.boolean("network.http.http2.allow-push", false),
		pushMaxConcurrent:   derivePushMaxConcurrent(prefs, files[firefoxSessionPath]),
		headerTableSize:     prefs.requiredNumber("network.http.http2.default-hpack-buffer"),
		initialWindowSize:   prefs.requiredNumber("network.http.http2.push-allowance"),
	}

	pullAllowance := prefs.requiredNumber("network.http.http2.pull-allowance")

	if prefs.err != nil {
		return firefoxFeatures{}, prefs.err
	}

	sessionWindow := max(features.initialWindowSize, pullAllowance)
	if sessionWindow > initialHTTP2Window {
		features.connectionFlow = sessionWindow - initialHTTP2Window
	}

	return features, nil
}

// derivePostQuantum returns the post-quantum key share security.tls.enable_kyber
// enables: X25519MLKEM768 once the socket lists it, the Kyber draft before.
func derivePostQuantum(prefs *preferenceReader, socket string) postQuantum {
	if !prefs.boolean("security.tls.enable_kyber", false) {
		return postQuantumNone
	}

	if strings.Contains(socket, "ssl_grp_kem_mlkem768x25519") {
		return postQuantumMLKEM
	}

	return postQuantumKyber
}

// deriveFFDHE reports whether the FFDHE groups are offered. Firefox always
// offered them until the socket made them depend on the DHE cipher suite
// preferences (156).
func deriveFFDHE(prefs *preferenceReader, socket string) bool {
	if !strings.Contains(socket, "StaticPrefs::security_ssl3_dhe_rsa_aes_128_sha() ||") {
		return true
	}

	dhe128 := prefs.requiredBoolean("security.ssl3.dhe_rsa_aes_128_sha")
	dhe256 := prefs.requiredBoolean("security.ssl3.dhe_rsa_aes_256_sha")

	return dhe128 || dhe256
}

// deriveDisabledCiphers lists the suites of firefoxCipherPreferences whose
// preference is off.
func deriveDisabledCiphers(prefs *preferenceReader) []uint16 {
	var disabled []uint16

	for _, cipher := range firefoxCipherPreferences {
		if !prefs.requiredBoolean(cipher.name) {
			disabled = append(disabled, cipher.suite)
		}
	}

	return disabled
}

// deriveCertCompression lists the certificate compression algorithms whose
// preference is on, in advertised order.
func deriveCertCompression(prefs *preferenceReader) []utls.CertCompressionAlgo {
	var algorithms []utls.CertCompressionAlgo

	for _, compression := range firefoxCompressionPreferences {
		if prefs.boolean(compression.name, false) {
			algorithms = append(algorithms, compression.algorithm)
		}
	}

	return algorithms
}

// derivePushMaxConcurrent reports whether a build that disallows push sends
// MAX_CONCURRENT_STREAMS 0. Builds before the
// send-push-max-concurrent-frame preference wrote it whenever push was off.
func derivePushMaxConcurrent(prefs *preferenceReader, session string) bool {
	if strings.Contains(session, "network_http_http2_allow_push()") &&
		!strings.Contains(session, "network_http_http2_send_push_max_concurrent_frame()") {
		return true
	}

	return prefs.boolean("network.http.http2.send-push-max-concurrent-frame", false)
}

// checkMLDSAPolicy confirms that an enabled security.tls.enable_mldsa
// preference really adds the ML-DSA signature schemes, as the policy in
// nsNSSComponent.cpp and EnabledSignatureSchemes.h did when it was
// introduced.
func checkMLDSAPolicy(ctx context.Context, sources *fetcher, revision sourceRevision) error {
	files, err := sources.fetchFiles(ctx, revision, []string{
		firefoxComponentPath,
		firefoxSignaturesPath,
	})
	if err != nil {
		return err
	}

	signatures := files[firefoxSignaturesPath]
	policy := files[firefoxComponentPath]

	recognized := strings.Contains(signatures, "ssl_sig_mldsa44") &&
		strings.Contains(signatures, "ssl_sig_mldsa65") &&
		strings.Contains(signatures, "ssl_sig_mldsa87") &&
		strings.Contains(policy, "StaticPrefs::security_tls_enable_mldsa()")

	if !recognized {
		return errors.New("unrecognized ML-DSA signature policy")
	}

	return nil
}
