package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	http "github.com/aarock1234/fphttp/v2"
	"github.com/aarock1234/fphttp/v2/browser"
)

type chromiumDefinition struct {
	Version              string           `json:"version"`
	Platform             http.Platform    `json:"platform"`
	Hello                string           `json:"hello"`
	Shuffle              bool             `json:"shuffle"`
	NewALPS              bool             `json:"new_alps"`
	MLDSA                bool             `json:"mldsa"`
	SignatureGREASE      bool             `json:"signature_grease"`
	MaxConcurrentStreams uint32           `json:"max_concurrent_streams,omitempty"`
	PriorityHeader       bool             `json:"priority_header"`
	SettingsGREASE       bool             `json:"settings_grease"`
	H2Verified           bool             `json:"h2_verified"`
	TrustAnchorIDs       [][]byte         `json:"trust_anchor_ids,omitempty"`
	Sources              []browser.Source `json:"sources"`
}

var boringRevisionPattern = regexp.MustCompile(`'boringssl_revision':\s*'([a-f0-9]{40})'`)
var trustAnchorPattern = regexp.MustCompile(`trust_anchor_id:\s*"((?:\\x[a-fA-F0-9]{2})+)"`)
var verifyPreferencesPattern = regexp.MustCompile(`static const uint16_t kVerifyPrefs\[\]\s*=\s*\{([^}]+)\}`)

func (i *importer) chromiumSources(ctx context.Context, entries []browser.Descriptor) ([]chromiumDefinition, error) {
	selected := make(map[string]browser.Descriptor)
	for _, entry := range entries {
		if entry.Browser != http.BrowserChrome || entry.Platform == http.PlatformIOS || entry.Platform == http.PlatformIPadOS {
			continue
		}
		major := strings.Split(entry.Version, ".")[0]
		key := string(entry.Platform) + "/" + entry.Channel + "/" + major
		previous, found := selected[key]
		if !found || newerVersion(entry.Version, previous.Version) {
			selected[key] = entry
		}
		if entry.Version == "144.0.7559.135" || entry.Version == "146.0.7680.180" ||
			entry.Version == "150.0.7871.189" || entry.Version == "152.0.7977.85" {
			selected[string(entry.Platform)+"/exact/"+entry.Version] = entry
		}
	}

	versions := make(map[string]map[string]string)
	var definitions []chromiumDefinition
	for _, entry := range selected {
		sources, found := versions[entry.Version]
		if !found {
			var err error
			sources, err = i.chromiumSourceFiles(ctx, entry.Version)
			if err != nil {
				fmt.Printf("  unavailable %s: %v\n", entry.Version, err)
				continue
			}
			versions[entry.Version] = sources
		}
		definition, err := deriveChromium(entry, sources)
		if err != nil {
			fmt.Printf("  unavailable %s on %s: %v\n", entry.Version, entry.Platform, err)
			continue
		}
		definitions = append(definitions, definition)
	}
	slices.SortFunc(definitions, func(a, b chromiumDefinition) int {
		return strings.Compare(string(a.Platform)+"/"+a.Version, string(b.Platform)+"/"+b.Version)
	})

	return definitions, nil
}

func (i *importer) chromiumSourceFiles(ctx context.Context, version string) (map[string]string, error) {
	paths := []string{
		"DEPS",
		"net/base/features.cc",
		"net/socket/ssl_client_socket_impl.cc",
		"net/ssl/ssl_config_service.cc",
		"net/ssl/ssl_config_service.h",
		"net/http/http_network_session.cc",
		"net/http/http_network_session.h",
		"net/spdy/spdy_session.cc",
		"net/spdy/spdy_http_utils.cc",
	}
	if versionMajor(version) >= 152 {
		paths = append(paths, "net/data/ssl/chrome_root_store/root_store.textproto")
	}
	type sourceResult struct {
		path string
		data []byte
		err  error
	}
	results := make(chan sourceResult, len(paths))
	var workers sync.WaitGroup
	for _, path := range paths {
		workers.Go(func() {
			url := "https://raw.githubusercontent.com/chromium/chromium/" + version + "/" + path
			data, err := i.fetch(ctx, url)
			results <- sourceResult{
				path: path,
				data: data,
				err:  err,
			}
		})
	}
	workers.Wait()
	close(results)
	files := make(map[string]string, len(paths))
	var failures []error
	for result := range results {
		if result.err != nil {
			failures = append(failures, result.err)
			continue
		}
		files[result.path] = string(result.data)
	}
	if len(failures) > 0 {
		return nil, errors.Join(failures...)
	}

	return files, nil
}

func deriveChromium(entry browser.Descriptor, files map[string]string) (chromiumDefinition, error) {
	features := files["net/base/features.cc"]
	socket := files["net/socket/ssl_client_socket_impl.cc"]
	configuration := files["net/ssl/ssl_config_service.cc"]
	defaults := files["net/ssl/ssl_config_service.h"]
	flag := func(name string, absent bool) (bool, error) {
		return featureDefault(features, name, entry.Platform, absent)
	}
	shuffle, err := flag("kPermuteTLSExtensions", strings.Contains(socket, "SSL_set_permute_extensions(ssl_.get(), 1)"))
	if err != nil {
		return chromiumDefinition{}, err
	}
	pq, err := flag("kPostQuantumKyber", strings.Contains(configuration, "SSL_GROUP_X25519_MLKEM768"))
	if err != nil {
		return chromiumDefinition{}, err
	}
	ech, err := flag("kEncryptedClientHello", strings.Contains(defaults, "ech_enabled = true"))
	if err != nil {
		return chromiumDefinition{}, err
	}
	newALPS, err := flag("kUseNewAlpsCodepointHttp2", false)
	if err != nil {
		return chromiumDefinition{}, err
	}
	preferences := verifyPreferencesPattern.FindStringSubmatch(socket)
	unconditionalMLDSA := len(preferences) == 2 && strings.Contains(preferences[1], "SSL_SIGN_ML_DSA_44") &&
		strings.Contains(preferences[1], "SSL_SIGN_ML_DSA_65") && strings.Contains(preferences[1], "SSL_SIGN_ML_DSA_87")
	mldsa, err := flag("kTlsMldsaSignatures", unconditionalMLDSA)
	if err != nil {
		return chromiumDefinition{}, err
	}
	signatureGREASE, err := flag("kTlsGreaseSigalgs", false)
	if err != nil {
		return chromiumDefinition{}, err
	}
	trustAnchors, err := flag("kTLSTrustAnchorIDs", false)
	if err != nil {
		return chromiumDefinition{}, err
	}
	nonMTC, err := flag("kNonMtcTrustAnchorIDs", false)
	if err != nil {
		return chromiumDefinition{}, err
	}
	prioritySource := files["net/spdy/spdy_http_utils.cc"]
	priorityDefault := strings.Contains(prioritySource, "SerializePriorityFieldValue") &&
		!strings.Contains(prioritySource, "kPriorityHeader")
	priorityHeader, err := flag("kPriorityHeader", priorityDefault)
	if err != nil {
		return chromiumDefinition{}, err
	}
	definition := chromiumDefinition{
		Version:         entry.Version,
		Platform:        entry.Platform,
		Hello:           "classical",
		Shuffle:         shuffle,
		NewALPS:         newALPS,
		MLDSA:           mldsa,
		SignatureGREASE: signatureGREASE,
		PriorityHeader:  priorityHeader,
		SettingsGREASE:  strings.Contains(files["net/spdy/spdy_session.cc"], "0x0a0a") && strings.Contains(files["net/spdy/spdy_session.cc"], "enable_http2_settings_grease_"),
		H2Verified:      verifiedChromiumH2(files),
	}
	if pq && (strings.Contains(configuration, "MLKEM768") || strings.Contains(socket, "MLKEM768")) {
		definition.Hello = "mlkem"
	} else if pq {
		definition.Hello = "kyber"
	} else if ech {
		definition.Hello = "ech"
	}
	if !strings.Contains(files["net/socket/ssl_client_socket_impl.cc"], "SSL_set_strict_cipher_list") ||
		!strings.Contains(files["net/spdy/spdy_session.cc"], "SendInitialData") {
		return chromiumDefinition{}, fmt.Errorf("unrecognized TLS/H2 source configuration")
	}
	if strings.Contains(files["net/http/http_network_session.cc"], "SETTINGS_MAX_CONCURRENT_STREAMS") {
		definition.MaxConcurrentStreams = 1000
	}
	if trustAnchors && nonMTC {
		for _, match := range trustAnchorPattern.FindAllStringSubmatch(files["net/data/ssl/chrome_root_store/root_store.textproto"], -1) {
			id, err := hex.DecodeString(strings.ReplaceAll(match[1], `\x`, ""))
			if err != nil {
				return chromiumDefinition{}, fmt.Errorf("decode root-store trust anchor: %w", err)
			}
			definition.TrustAnchorIDs = append(definition.TrustAnchorIDs, id)
		}
		slices.SortFunc(definition.TrustAnchorIDs, bytes.Compare)
		if len(definition.TrustAnchorIDs) == 0 {
			return chromiumDefinition{}, fmt.Errorf("enabled trust anchors have no source IDs")
		}
	}

	for _, path := range []string{
		"net/base/features.cc",
		"net/socket/ssl_client_socket_impl.cc",
		"net/ssl/ssl_config_service.cc",
		"net/http/http_network_session.cc",
		"net/spdy/spdy_session.cc",
		"net/spdy/spdy_http_utils.cc",
	} {
		definition.Sources = append(definition.Sources, browser.Source{
			URL:      "https://github.com/chromium/chromium/blob/" + entry.Version + "/" + path,
			Revision: entry.Version,
			Note:     "Compiled default configuration; runtime variations are separate evidence.",
		})
	}
	match := boringRevisionPattern.FindStringSubmatch(files["DEPS"])
	if len(match) != 2 {
		return chromiumDefinition{}, fmt.Errorf("missing pinned BoringSSL revision")
	}
	definition.Sources = append(definition.Sources, browser.Source{
		URL:      "https://github.com/google/boringssl/blob/" + match[1] + "/ssl/extensions.cc",
		Revision: match[1],
		Note:     "BoringSSL revision pinned by this Chromium DEPS file; uTLS parameter families are not a complete BoringSSL implementation.",
	})
	if len(definition.TrustAnchorIDs) > 0 {
		definition.Sources = append(definition.Sources, browser.Source{
			URL:      "https://github.com/chromium/chromium/blob/" + entry.Version + "/net/data/ssl/chrome_root_store/root_store.textproto",
			Revision: entry.Version,
			Note:     "Bundled root-store IDs; this profile sorts them deterministically, whereas Chrome iterates an unordered set and downloaded components can replace the bundle.",
		})
	}

	return definition, nil
}

func verifiedChromiumH2(files map[string]string) bool {
	compact := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "")
	configuration := compact.Replace(files["net/http/http_network_session.cc"] + files["net/http/http_network_session.h"])
	for _, expected := range []string{
		"kSpdyMaxHeaderTableSize=64*1024;",
		"kSpdyMaxHeaderListSize=256*1024;",
		"kSpdyStreamMaxRecvWindowSize=6*1024*1024;",
		"kSpdySessionMaxRecvWindowSize=15*1024*1024;",
		"kSpdyDisablePush=0;",
		"spdy_session_max_recv_window_size(kSpdySessionMaxRecvWindowSize)",
		"enable_http2_settings_grease=false;",
		"http2_end_stream_with_data_frame=false;",
		"enable_priority_update=false;",
	} {
		if !strings.Contains(configuration, expected) {
			return false
		}
	}
	if strings.Contains(configuration, "SETTINGS_MAX_CONCURRENT_STREAMS") &&
		!strings.Contains(configuration, "kSpdyMaxConcurrentPushedStreams=1000;") {
		return false
	}
	session := compact.Replace(files["net/spdy/spdy_session.cc"])
	for _, expected := range []string{
		"IsSpdySettingAtDefaultInitialValue(setting.first,setting.second)",
		"settings_map.insert(setting)",
		"session_max_recv_window_size_-session_recv_window_size_",
		"CreateSettings(settings_map)",
	} {
		if !strings.Contains(session, expected) {
			return false
		}
	}

	return true
}

func featureDefault(source, name string, platform http.Platform, absent bool) (bool, error) {
	start := strings.Index(source, "BASE_FEATURE("+name+",")
	if start < 0 {
		return absent, nil
	}
	declaration := source[start:]
	end := strings.Index(declaration, ");")
	if end < 0 {
		return false, fmt.Errorf("unterminated feature declaration %s", name)
	}
	if conditional := strings.Index(declaration, "#if"); conditional >= 0 && conditional < end {
		closing := strings.Index(declaration, "#endif")
		if closing < 0 {
			return false, fmt.Errorf("unterminated feature condition %s", name)
		}
		end = closing + len("#endif")
	}
	declaration = declaration[:end]
	if strings.Contains(declaration, "#if BUILDFLAG(IS_ANDROID)") {
		branches := strings.SplitN(declaration, "#else", 2)
		if len(branches) != 2 {
			return false, fmt.Errorf("unrecognized Android feature branches for %s", name)
		}
		if platform == http.PlatformAndroid {
			return strings.Contains(branches[0], "FEATURE_ENABLED_BY_DEFAULT"), nil
		}

		return strings.Contains(branches[1], "FEATURE_ENABLED_BY_DEFAULT"), nil
	}
	if strings.Contains(declaration, "#") ||
		(!strings.Contains(declaration, "FEATURE_ENABLED_BY_DEFAULT") && !strings.Contains(declaration, "FEATURE_DISABLED_BY_DEFAULT")) {
		return false, fmt.Errorf("unrecognized compiled feature declaration %s", name)
	}

	return strings.Contains(declaration, "FEATURE_ENABLED_BY_DEFAULT"), nil
}

func versionMajor(version string) int {
	major, _ := strconv.Atoi(strings.Split(version, ".")[0])

	return major
}

func newerVersion(a, b string) bool {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	for index := range max(len(aParts), len(bParts)) {
		var aPart, bPart int
		if index < len(aParts) {
			aPart, _ = strconv.Atoi(aParts[index])
		}
		if index < len(bParts) {
			bPart, _ = strconv.Atoi(bParts[index])
		}
		if aPart != bPart {
			return aPart > bPart
		}
	}

	return false
}
