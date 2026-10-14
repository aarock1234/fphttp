package browser

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"

	utls "github.com/refraction-networking/utls"

	http "github.com/aarock1234/fphttp"
)

//go:embed data/chromium.json
var chromiumData []byte

type chromiumDefinition struct {
	Version              string        `json:"version"`
	Platform             http.Platform `json:"platform"`
	Hello                string        `json:"hello"`
	Shuffle              bool          `json:"shuffle"`
	NewALPS              bool          `json:"new_alps"`
	MLDSA                bool          `json:"mldsa"`
	SignatureGREASE      bool          `json:"signature_grease"`
	MaxConcurrentStreams uint32        `json:"max_concurrent_streams,omitempty"`
	PriorityHeader       bool          `json:"priority_header"`
	SettingsGREASE       bool          `json:"settings_grease"`
	H2Verified           bool          `json:"h2_verified"`
	TrustAnchorIDs       [][]byte      `json:"trust_anchor_ids,omitempty"`
	Sources              []Source      `json:"sources"`
}

var chromiumDefinitions = loadChromiumDefinitions()

func loadChromiumDefinitions() map[string]chromiumDefinition {
	var definitions []chromiumDefinition
	if err := json.Unmarshal(chromiumData, &definitions); err != nil {
		panic(fmt.Sprintf("browser: invalid Chromium definitions: %v", err))
	}

	indexed := make(map[string]chromiumDefinition, len(definitions))
	for _, definition := range definitions {
		indexed[string(definition.Platform)+"/"+definition.Version] = definition
	}

	return indexed
}

func chromiumFingerprint(definition chromiumDefinition) *http.Fingerprint {
	fingerprint := http.Chrome133()
	fingerprint.ClientHelloID = utls.ClientHelloID{}
	fingerprint.ClientHelloSpecFactory = func() (*utls.ClientHelloSpec, error) {
		return chromiumHello(definition)
	}
	fingerprint.HeaderOrder = []string{"Host"}
	if definition.MaxConcurrentStreams != 0 {
		fingerprint.H2.Settings = slices.Insert(fingerprint.H2.Settings, 2, http.H2Setting{
			ID:  http.H2SettingMaxConcurrentStreams,
			Val: definition.MaxConcurrentStreams,
		})
	}

	return fingerprint
}

func chromiumHello(definition chromiumDefinition) (*utls.ClientHelloSpec, error) {
	var helloID utls.ClientHelloID
	switch definition.Hello {
	case "classical":
		helloID = utls.HelloChrome_102
	case "ech":
		helloID = utls.HelloChrome_120
	case "kyber":
		helloID = utls.HelloChrome_120_PQ
	case "mlkem":
		helloID = utls.HelloChrome_131
	default:
		return nil, fmt.Errorf("unknown reviewed Chromium hello %q", definition.Hello)
	}

	spec, err := utls.UTLSIdToSpec(helloID)
	if err != nil {
		return nil, fmt.Errorf("construct Chromium hello: %w", err)
	}
	for index, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *utls.ApplicationSettingsExtension:
			if definition.NewALPS {
				spec.Extensions[index] = &utls.ApplicationSettingsExtensionNew{
					SupportedProtocols: slices.Clone(extension.SupportedProtocols),
				}
			}
		case *utls.SignatureAlgorithmsExtension:
			algorithms := slices.Clone(extension.SupportedSignatureAlgorithms)
			if definition.MLDSA {
				algorithms = append([]utls.SignatureScheme{
					utls.MLDSA44,
					utls.MLDSA65,
					utls.MLDSA87,
				}, algorithms...)
			}
			if definition.SignatureGREASE {
				algorithms = append([]utls.SignatureScheme{utls.GREASE_PLACEHOLDER}, algorithms...)
			}
			extension.SupportedSignatureAlgorithms = algorithms
		}
	}
	if len(definition.TrustAnchorIDs) > 0 {
		ids := make([][]byte, len(definition.TrustAnchorIDs))
		for index, id := range definition.TrustAnchorIDs {
			ids[index] = slices.Clone(id)
		}
		last := len(spec.Extensions) - 1
		spec.Extensions = slices.Insert(spec.Extensions, last, utls.TLSExtension(&utls.TrustAnchorsExtension{TrustAnchorIDs: ids}))
	}
	if definition.Shuffle {
		spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
	}

	return &spec, nil
}
