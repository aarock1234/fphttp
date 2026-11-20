package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/aarock1234/fphttp/v2/internal/releasefetch"
)

// Chromium source files that locate and hold the bundled BoringSSL, relative
// to the Chromium repository root.
const (
	chromiumDEPSPath       = "DEPS"
	boringSSLExtensionPath = "third_party/boringssl/src/ssl/extensions.cc"
)

// firstSigalgGREASEMajor is the first Chromium major that could send
// signature algorithm GREASE, behind the TlsGreaseSigalgs feature. Earlier
// builds have neither the feature nor BoringSSL support for it.
const firstSigalgGREASEMajor = 152

// boringSSLRevisionPattern matches the BoringSSL commit Chromium's DEPS
// pins.
var boringSSLRevisionPattern = regexp.MustCompile(`'boringssl_revision':\s*'([0-9a-f]{40})'`)

// sigalgGREASERetired reports whether a build at tag dropped the
// TlsGreaseSigalgs switch: from 158 the socket no longer opts in, because
// BoringSSL sends signature algorithm GREASE whenever GREASE is enabled.
// Only then does the derivation need BoringSSL's source.
func sigalgGREASERetired(socket, tag string) bool {
	return versionMajor(tag) >= firstSigalgGREASEMajor &&
		!strings.Contains(socket, "SSL_CTX_set_grease_sigalgs_enabled")
}

// fetchBoringSSLExtensions returns BoringSSL's ssl/extensions.cc at the
// commit that Chromium revision pins in DEPS.
func fetchBoringSSLExtensions(ctx context.Context, sources *releasefetch.Fetcher, revision sourceRevision) (string, error) {
	deps, err := fetchFile(ctx, sources, revision, chromiumDEPSPath)
	if err != nil {
		return "", err
	}

	match := boringSSLRevisionPattern.FindStringSubmatch(deps)
	if match == nil {
		return "", fmt.Errorf("%s %s: no boringssl_revision", revision.name, chromiumDEPSPath)
	}

	boringSSL := sourceRevision{
		name: "boringssl " + match[1],
		mirrors: []string{
			"https://raw.githubusercontent.com/google/boringssl/" + match[1] + "/",
		},
	}

	return fetchFile(ctx, sources, boringSSL, "ssl/extensions.cc")
}

// sigalgGREASEByDefault reports whether a build without the
// TlsGreaseSigalgs feature sends signature algorithm GREASE: the socket
// must enable GREASE, and BoringSSL must add the GREASE signature algorithm
// under that switch alone rather than a separate sigalgs one.
func sigalgGREASEByDefault(files sourceFiles) bool {
	if !strings.Contains(files[chromiumSocketPath], "SSL_CTX_set_grease_enabled(ssl_ctx_.get(), 1)") {
		return false
	}

	extensions := files[boringSSLExtensionPath]

	return strings.Contains(extensions, "ssl_grease_signature_algorithm") &&
		!strings.Contains(extensions, "grease_sigalgs")
}
