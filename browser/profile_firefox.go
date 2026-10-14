package browser

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"

	utls "github.com/refraction-networking/utls"

	http "github.com/aarock1234/fphttp"
)

//go:embed data/firefox.json
var firefoxData []byte

type firefoxDefinition struct {
	Version           string        `json:"version"`
	Platform          http.Platform `json:"platform"`
	Channel           string        `json:"channel"`
	ECH               bool          `json:"ech"`
	PQ                string        `json:"pq,omitempty"`
	SCT               bool          `json:"sct"`
	MLDSA             bool          `json:"mldsa"`
	FFDHE             bool          `json:"ffdhe"`
	DisabledCiphers   []uint16      `json:"disabled_ciphers,omitempty"`
	Compression       []uint16      `json:"compression,omitempty"`
	LegacyTree        bool          `json:"legacy_tree"`
	NoPriorities      bool          `json:"no_priorities"`
	AllowPush         bool          `json:"allow_push"`
	PushMaxConcurrent bool          `json:"push_max_concurrent"`
	HeaderTableSize   uint32        `json:"header_table_size"`
	InitialWindowSize uint32        `json:"initial_window_size"`
	ConnectionFlow    uint32        `json:"connection_flow"`
	Sources           []Source      `json:"sources"`
}

var firefoxDefinitions = loadFirefoxDefinitions()

func loadFirefoxDefinitions() map[string]firefoxDefinition {
	var definitions []firefoxDefinition
	if err := json.Unmarshal(firefoxData, &definitions); err != nil {
		panic(fmt.Sprintf("browser: invalid Firefox definitions: %v", err))
	}
	indexed := make(map[string]firefoxDefinition, len(definitions))
	for _, definition := range definitions {
		indexed[firefoxDefinitionKey(definition.Platform, definition.Channel, definition.Version)] = definition
	}

	return indexed
}

func firefoxDefinitionKey(platform http.Platform, channel, version string) string {
	return string(platform) + "/" + channel + "/" + version
}

func firefoxFingerprint(definition firefoxDefinition) *http.Fingerprint {
	fingerprint := http.Firefox120()
	fingerprint.ClientHelloID = utls.ClientHelloID{}
	fingerprint.ClientHelloSpecFactory = func() (*utls.ClientHelloSpec, error) {
		return firefoxHello(definition)
	}
	fingerprint.HeaderOrder = []string{"Host"}
	fingerprint.H2.Settings = []http.H2Setting{
		{
			ID:  http.H2SettingHeaderTableSize,
			Val: definition.HeaderTableSize,
		},
		{
			ID:  http.H2SettingEnablePush,
			Val: 0,
		},
	}
	if definition.PushMaxConcurrent {
		fingerprint.H2.Settings = append(fingerprint.H2.Settings, http.H2Setting{
			ID:  http.H2SettingMaxConcurrentStreams,
			Val: 0,
		})
	}
	fingerprint.H2.Settings = append(fingerprint.H2.Settings,
		http.H2Setting{
			ID:  http.H2SettingInitialWindowSize,
			Val: definition.InitialWindowSize,
		},
		http.H2Setting{
			ID:  http.H2SettingMaxFrameSize,
			Val: 16384,
		},
	)
	fingerprint.H2.ConnectionFlow = definition.ConnectionFlow
	if !definition.LegacyTree {
		fingerprint.H2.InitialStreamID = 3
		fingerprint.H2.InitPriorityFrames = nil
		fingerprint.H2.HeaderPriority = http.H2Priority{}
	}
	if definition.NoPriorities && !definition.LegacyTree {
		fingerprint.H2.Settings = append(fingerprint.H2.Settings, http.H2Setting{
			ID:  http.H2SettingNoRFC7540Priorities,
			Val: 1,
		})
	}

	return fingerprint
}

func firefoxHello(definition firefoxDefinition) (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloFirefox_120)
	if err != nil {
		return nil, fmt.Errorf("construct Firefox hello: %w", err)
	}
	spec.CipherSuites = slices.DeleteFunc(spec.CipherSuites, func(cipher uint16) bool {
		return slices.Contains(definition.DisabledCiphers, cipher)
	})
	var group utls.CurveID
	switch definition.PQ {
	case "kyber":
		group = utls.X25519Kyber768Draft00
	case "mlkem":
		group = utls.X25519MLKEM768
	}
	extensions := make([]utls.TLSExtension, 0, len(spec.Extensions)+2)
	for _, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *utls.SupportedCurvesExtension:
			if !definition.FFDHE {
				extension.Curves = slices.DeleteFunc(extension.Curves, func(curve utls.CurveID) bool {
					return curve == utls.FakeCurveFFDHE2048 || curve == utls.FakeCurveFFDHE3072
				})
			}
			if group != 0 {
				extension.Curves = append([]utls.CurveID{group}, extension.Curves...)
			}
		case *utls.KeyShareExtension:
			if group != 0 {
				extension.KeyShares = append([]utls.KeyShare{{Group: group}}, extension.KeyShares...)
			}
		case *utls.SignatureAlgorithmsExtension:
			if definition.MLDSA {
				extension.SupportedSignatureAlgorithms = append(extension.SupportedSignatureAlgorithms,
					utls.MLDSA44, utls.MLDSA65, utls.MLDSA87)
			}
		case *utls.FakeDelegatedCredentialsExtension:
			extensions = append(extensions, extension)
			if definition.SCT {
				extensions = append(extensions, &utls.SCTExtension{})
			}
			continue
		case *utls.GREASEEncryptedClientHelloExtension:
			if len(definition.Compression) > 0 {
				algorithms := make([]utls.CertCompressionAlgo, len(definition.Compression))
				for index, algorithm := range definition.Compression {
					algorithms[index] = utls.CertCompressionAlgo(algorithm)
				}
				extensions = append(extensions, &utls.UtlsCompressCertExtension{Algorithms: algorithms})
			}
			if !definition.ECH {
				continue
			}
		}
		extensions = append(extensions, extension)
	}
	spec.Extensions = slices.Clone(extensions)

	return &spec, nil
}
