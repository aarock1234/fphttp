package http

import (
	utls "github.com/refraction-networking/utls"
)

// Firefox returns the versioned Firefox 144 baseline from published captures.
func Firefox() *Fingerprint {
	return Firefox144()
}

// Firefox120 uses uTLS's Firefox 120 ClientHello with the historical HTTP/2
// dependency tree. All six priority nodes precede the first request on stream 15.
func Firefox120() *Fingerprint {
	profile := firefoxProfile()
	profile.ClientHelloID = utls.HelloFirefox_120
	profile.H2.InitPriorityFrames = []H2PriorityFrame{
		{
			StreamID:  3,
			StreamDep: 0,
			Weight:    200,
		},
		{
			StreamID:  5,
			StreamDep: 0,
			Weight:    100,
		},
		{
			StreamID:  7,
			StreamDep: 0,
			Weight:    0,
		},
		{
			StreamID:  9,
			StreamDep: 7,
			Weight:    0,
		},
		{
			StreamID:  11,
			StreamDep: 3,
			Weight:    0,
		},
		{
			StreamID:  13,
			StreamDep: 0,
			Weight:    240,
		},
	}
	profile.H2.HeaderPriority = H2Priority{
		Enabled:   true,
		StreamDep: 13,
		Weight:    41,
	}

	return profile
}

// Firefox144 models the published Firefox 144 TLS parameter set and HTTP/2
// frames. It includes ML-KEM, SCT, certificate compression, and no legacy
// priority frames. ECH GREASE uses uTLS's Firefox implementation.
func Firefox144() *Fingerprint {
	profile := firefoxProfile()
	profile.ClientHelloSpecFactory = firefox144ClientHello
	profile.HeaderOrder = []string{
		"Host",
		"Connection",
		"User-Agent",
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
		"Upgrade-Insecure-Requests",
		"Sec-Fetch-Dest",
		"Sec-Fetch-Mode",
		"Sec-Fetch-Site",
		"Sec-Fetch-User",
		"Priority",
		"Te",
	}

	return profile
}

func firefoxProfile() *Fingerprint {
	return &Fingerprint{
		PseudoHeaderOrder: []string{
			":method",
			":path",
			":authority",
			":scheme",
		},
		H2: H2Fingerprint{
			Settings: []H2Setting{
				{
					ID:  H2SettingHeaderTableSize,
					Val: 65536,
				},
				{
					ID:  H2SettingEnablePush,
					Val: 0,
				},
				{
					ID:  H2SettingInitialWindowSize,
					Val: 131072,
				},
				{
					ID:  H2SettingMaxFrameSize,
					Val: 16384,
				},
			},
			ConnectionFlow:  12517377,
			InitialStreamID: 15,
		},
	}
}

func firefox144ClientHello() (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloFirefox_120)
	if err != nil {
		return nil, err
	}

	extensions := make([]utls.TLSExtension, 0, len(spec.Extensions)+2)
	for _, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *utls.SupportedCurvesExtension:
			extension.Curves = append([]utls.CurveID{utls.X25519MLKEM768}, extension.Curves...)
		case *utls.KeyShareExtension:
			extension.KeyShares = append([]utls.KeyShare{{Group: utls.X25519MLKEM768}}, extension.KeyShares...)
		case *utls.FakeDelegatedCredentialsExtension:
			extensions = append(extensions, extension, &utls.SCTExtension{})
			continue
		case *utls.GREASEEncryptedClientHelloExtension:
			extensions = append(extensions, &utls.UtlsCompressCertExtension{
				Algorithms: []utls.CertCompressionAlgo{
					utls.CertCompressionZlib,
					utls.CertCompressionBrotli,
					utls.CertCompressionZstd,
				},
			})
		}
		extensions = append(extensions, extension)
	}
	spec.Extensions = extensions

	return &spec, nil
}
