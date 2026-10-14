package main

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	http "github.com/aarock1234/fphttp"
	"github.com/aarock1234/fphttp/browser"
)

type firefoxDefinition struct {
	Version           string           `json:"version"`
	Platform          http.Platform    `json:"platform"`
	Channel           string           `json:"channel"`
	ECH               bool             `json:"ech"`
	PQ                string           `json:"pq,omitempty"`
	SCT               bool             `json:"sct"`
	MLDSA             bool             `json:"mldsa"`
	FFDHE             bool             `json:"ffdhe"`
	DisabledCiphers   []uint16         `json:"disabled_ciphers,omitempty"`
	Compression       []uint16         `json:"compression,omitempty"`
	LegacyTree        bool             `json:"legacy_tree"`
	NoPriorities      bool             `json:"no_priorities"`
	AllowPush         bool             `json:"allow_push"`
	PushMaxConcurrent bool             `json:"push_max_concurrent"`
	HeaderTableSize   uint32           `json:"header_table_size"`
	InitialWindowSize uint32           `json:"initial_window_size"`
	ConnectionFlow    uint32           `json:"connection_flow"`
	Sources           []browser.Source `json:"sources"`
}

func (i *importer) firefoxSources(ctx context.Context, entries []browser.Descriptor) []firefoxDefinition {
	selected := make(map[string]browser.Descriptor)
	for _, entry := range entries {
		if entry.Browser != http.BrowserFirefox || entry.EngineVersion == "" ||
			entry.Platform == http.PlatformIOS || entry.Platform == http.PlatformIPadOS {
			continue
		}
		key := string(entry.Platform) + "/" + entry.Channel + "/" + strings.Split(entry.Version, ".")[0]
		previous, found := selected[key]
		if !found || newerVersion(entry.Version, previous.Version) {
			selected[key] = entry
		}
	}

	cache := make(map[string]map[string]string)
	failures := make(map[string]bool)
	var definitions []firefoxDefinition
	for _, entry := range selected {
		tag := "FIREFOX_" + strings.ReplaceAll(entry.Version, ".", "_")
		if entry.Channel == "esr" {
			tag += "esr"
		}
		tag += "_RELEASE"
		if failures[tag] {
			continue
		}
		files, found := cache[tag]
		if !found {
			var err error
			files, err = i.firefoxSourceFiles(ctx, tag)
			if err != nil {
				fmt.Printf("  unavailable Firefox %s: %v\n", entry.Version, err)
				failures[tag] = true
				continue
			}
			cache[tag] = files
		}
		definition, err := deriveFirefox(entry, tag, files)
		if err != nil {
			fmt.Printf("  unavailable Firefox %s on %s: %v\n", entry.Version, entry.Platform, err)
			continue
		}
		definitions = append(definitions, definition)
	}
	slices.SortFunc(definitions, func(a, b firefoxDefinition) int {
		return strings.Compare(string(a.Platform)+"/"+a.Channel+"/"+a.Version, string(b.Platform)+"/"+b.Channel+"/"+b.Version)
	})

	return definitions
}

func (i *importer) firefoxSourceFiles(ctx context.Context, tag string) (map[string]string, error) {
	paths := []string{
		"modules/libpref/init/StaticPrefList.yaml",
		"security/nss/TAG-INFO",
		"security/manager/ssl/nsNSSIOLayer.cpp",
		"security/manager/ssl/nsNSSComponent.cpp",
		"netwerk/protocol/http/Http2Session.cpp",
	}
	files := make(map[string]string, len(paths))
	for _, path := range paths {
		url := "https://raw.githubusercontent.com/mozilla-firefox/firefox/" + tag + "/" + path
		data, err := i.fetch(ctx, url)
		if err != nil {
			if path == "security/nss/TAG-INFO" {
				headerURL := "https://raw.githubusercontent.com/mozilla-firefox/firefox/" + tag + "/security/nss/lib/nss/nss.h"
				header, headerErr := i.fetch(ctx, headerURL)
				if headerErr == nil {
					match := nssVersionPattern.FindSubmatch(header)
					if len(match) == 2 {
						files[path] = "NSS " + string(match[1]) + " (version from vendored nss.h)"
						continue
					}
				}
			}
			return nil, err
		}
		files[path] = string(data)
	}
	if strings.Contains(files["security/manager/ssl/nsNSSIOLayer.cpp"], "EnabledSignatureSchemes.h") {
		path := "security/manager/ssl/EnabledSignatureSchemes.h"
		data, err := i.fetch(ctx, "https://raw.githubusercontent.com/mozilla-firefox/firefox/"+tag+"/"+path)
		if err != nil {
			return nil, err
		}
		files[path] = string(data)
	}

	return files, nil
}

var nssVersionPattern = regexp.MustCompile(`#define NSS_VERSION\s+"([0-9]+(?:\.[0-9]+)+)"`)

func deriveFirefox(entry browser.Descriptor, tag string, files map[string]string) (firefoxDefinition, error) {
	prefs := files["modules/libpref/init/StaticPrefList.yaml"]
	values := make(map[string]string)
	declarations := []struct {
		name   string
		absent string
	}{
		{
			name:   "security.tls.ech.grease_probability",
			absent: "0",
		},
		{
			name:   "security.pki.certificate_transparency.mode",
			absent: "0",
		},
		{
			name:   "security.tls.enable_kyber",
			absent: "false",
		},
		{
			name:   "security.tls.enable_mldsa",
			absent: "false",
		},
		{name: "security.ssl3.ecdhe_ecdsa_aes_128_sha"},
		{name: "security.ssl3.ecdhe_ecdsa_aes_256_sha"},
		{name: "security.ssl3.dhe_rsa_aes_128_sha"},
		{name: "security.ssl3.dhe_rsa_aes_256_sha"},
		{
			name:   "security.tls.enable_certificate_compression_zlib",
			absent: "false",
		},
		{
			name:   "security.tls.enable_certificate_compression_brotli",
			absent: "false",
		},
		{
			name:   "security.tls.enable_certificate_compression_zstd",
			absent: "false",
		},
		{
			name:   "network.http.http2.enabled.deps",
			absent: "false",
		},
		{
			name:   "network.http.http2.send_NO_RFC7540_PRI",
			absent: "false",
		},
		{
			name:   "network.http.http2.allow-push",
			absent: "false",
		},
		{
			name:   "network.http.http2.send-push-max-concurrent-frame",
			absent: "false",
		},
		{name: "network.http.http2.default-hpack-buffer"},
		{name: "network.http.http2.push-allowance"},
		{name: "network.http.http2.pull-allowance"},
	}
	for _, declaration := range declarations {
		value, err := firefoxPreference(prefs, declaration.name, entry.Platform, declaration.absent)
		if err != nil {
			return firefoxDefinition{}, err
		}
		values[declaration.name] = value
	}
	ctMode, err := strconv.ParseUint(values["security.pki.certificate_transparency.mode"], 10, 32)
	if err != nil {
		return firefoxDefinition{}, fmt.Errorf("parse CT mode: %w", err)
	}
	greaseProbability, err := strconv.ParseUint(values["security.tls.ech.grease_probability"], 10, 32)
	if err != nil || greaseProbability > 100 {
		return firefoxDefinition{}, fmt.Errorf("invalid ECH GREASE probability %q", values["security.tls.ech.grease_probability"])
	}
	windowValues := make(map[string]uint32)
	for _, name := range []string{
		"network.http.http2.default-hpack-buffer",
		"network.http.http2.push-allowance",
		"network.http.http2.pull-allowance",
	} {
		value, err := strconv.ParseUint(values[name], 10, 32)
		if err != nil || value == 0 || value > 0x7fffffff {
			return firefoxDefinition{}, fmt.Errorf("unsupported %s value %q", name, values[name])
		}
		windowValues[name] = uint32(value)
	}
	session := files["netwerk/protocol/http/Http2Session.cpp"]
	definition := firefoxDefinition{
		Version:           entry.Version,
		Platform:          entry.Platform,
		Channel:           entry.Channel,
		ECH:               greaseProbability > 0,
		SCT:               ctMode != 0,
		FFDHE:             true,
		LegacyTree:        values["network.http.http2.enabled.deps"] == "true",
		NoPriorities:      values["network.http.http2.send_NO_RFC7540_PRI"] == "true",
		AllowPush:         values["network.http.http2.allow-push"] == "true",
		PushMaxConcurrent: values["network.http.http2.send-push-max-concurrent-frame"] == "true",
		HeaderTableSize:   windowValues["network.http.http2.default-hpack-buffer"],
		InitialWindowSize: windowValues["network.http.http2.push-allowance"],
	}
	if values["security.ssl3.ecdhe_ecdsa_aes_128_sha"] == "false" {
		definition.DisabledCiphers = append(definition.DisabledCiphers, 0xc009)
	}
	if values["security.ssl3.ecdhe_ecdsa_aes_256_sha"] == "false" {
		definition.DisabledCiphers = append(definition.DisabledCiphers, 0xc00a)
	}
	socket := files["security/manager/ssl/nsNSSIOLayer.cpp"]
	if strings.Contains(socket, "StaticPrefs::security_ssl3_dhe_rsa_aes_128_sha() ||") {
		definition.FFDHE = values["security.ssl3.dhe_rsa_aes_128_sha"] == "true" ||
			values["security.ssl3.dhe_rsa_aes_256_sha"] == "true"
	}
	if values["security.tls.enable_mldsa"] == "true" {
		signatures := files["security/manager/ssl/EnabledSignatureSchemes.h"]
		policy := files["security/manager/ssl/nsNSSComponent.cpp"]
		if !strings.Contains(signatures, "ssl_sig_mldsa44") ||
			!strings.Contains(signatures, "ssl_sig_mldsa65") ||
			!strings.Contains(signatures, "ssl_sig_mldsa87") ||
			!strings.Contains(policy, "StaticPrefs::security_tls_enable_mldsa()") {
			return firefoxDefinition{}, fmt.Errorf("unrecognized enabled MLDSA policy")
		}
		definition.MLDSA = true
	}
	initialWindow := max(windowValues["network.http.http2.push-allowance"], windowValues["network.http.http2.pull-allowance"])
	if initialWindow > 65535 {
		definition.ConnectionFlow = initialWindow - 65535
	}
	if strings.Contains(session, "network_http_http2_allow_push()") &&
		!strings.Contains(session, "network_http_http2_send_push_max_concurrent_frame()") {
		definition.PushMaxConcurrent = true
	}
	if values["security.tls.enable_kyber"] == "true" {
		definition.PQ = "kyber"
		if strings.Contains(files["security/manager/ssl/nsNSSIOLayer.cpp"], "ssl_grp_kem_mlkem768x25519") {
			definition.PQ = "mlkem"
		}
	}
	for index, name := range []string{
		"security.tls.enable_certificate_compression_zlib",
		"security.tls.enable_certificate_compression_brotli",
		"security.tls.enable_certificate_compression_zstd",
	} {
		if values[name] == "true" {
			definition.Compression = append(definition.Compression, uint16(index+1))
		}
	}
	for _, path := range []string{
		"modules/libpref/init/StaticPrefList.yaml",
		"security/manager/ssl/nsNSSIOLayer.cpp",
		"security/manager/ssl/nsNSSComponent.cpp",
		"netwerk/protocol/http/Http2Session.cpp",
	} {
		definition.Sources = append(definition.Sources, browser.Source{
			URL:      "https://github.com/mozilla-firefox/firefox/blob/" + tag + "/" + path,
			Revision: tag,
			Note:     "Release preference defaults and connection initialization; exact NSS wire encoding remains partially covered by uTLS.",
		})
	}
	if files["security/manager/ssl/EnabledSignatureSchemes.h"] != "" {
		definition.Sources = append(definition.Sources, browser.Source{
			URL:      "https://github.com/mozilla-firefox/firefox/blob/" + tag + "/security/manager/ssl/EnabledSignatureSchemes.h",
			Revision: tag,
			Note:     "Signature preferences are filtered by NSS algorithm policy; declaring MLDSA schemes does not enable them when the product preference is disabled.",
		})
	}
	nssPath := "security/nss/TAG-INFO"
	nssNote := "Exact NSS revision pinned by this Firefox release."
	if strings.Contains(files[nssPath], "version from vendored nss.h") {
		nssPath = "security/nss/lib/nss/nss.h"
		nssNote = "Vendored NSS version; this source provides a version rather than an upstream RTM tag."
	}
	definition.Sources = append(definition.Sources, browser.Source{
		URL:      "https://github.com/mozilla-firefox/firefox/blob/" + tag + "/" + nssPath,
		Revision: strings.TrimSpace(files["security/nss/TAG-INFO"]),
		Note:     nssNote,
	})

	return definition, nil
}
