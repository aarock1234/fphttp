package http

import (
	utls "github.com/refraction-networking/utls"
)

// Safari returns the Safari 27 macOS navigation profile from the supplied capture.
func Safari() *Fingerprint {
	return Safari27()
}

// Safari26 models Safari 26.0.1 on macOS, including ML-KEM and RFC 9218
// prioritization. Its TLS and HTTP/2 parameters also match the supplied
// iPhone Safari 27.0.1 capture.
func Safari26() *Fingerprint {
	return modernSafariProfile()
}

// Safari27 models the supplied Safari 27 macOS navigation capture. Its TLS and
// HTTP/2 connection parameters also match the captured iPhone Safari 27.0.1.
func Safari27() *Fingerprint {
	return modernSafariProfile()
}

// Safari27Fetch models the supplied Safari 27 macOS fetch header order.
// Its Pragma header precedes Sec-Fetch-Site, unlike the captured iPhone variation.
func Safari27Fetch() *Fingerprint {
	profile := modernSafariProfile()
	profile.HeaderOrder = []string{
		"Host",
		"Connection",
		"Accept",
		"Pragma",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"User-Agent",
		"Sec-Fetch-Dest",
		"Cache-Control",
		"Accept-Language",
		"Priority",
		"Accept-Encoding",
	}

	return profile
}

// SafariIOS returns the supplied iPhone Safari 27.0.1 profile.
func SafariIOS() *Fingerprint {
	return SafariIOS27()
}

// SafariIOS27 models the captured iPhone Safari 27.0.1 navigation request.
// Device model and reduced User-Agent values do not affect this profile.
func SafariIOS27() *Fingerprint {
	return modernSafariProfile()
}

// SafariIOS27Fetch models the captured iPhone fetch header ordering.
// Callers may use this order on individual requests without a second transport.
func SafariIOS27Fetch() *Fingerprint {
	profile := modernSafariProfile()
	profile.HeaderOrder = []string{
		"Host",
		"Connection",
		"Accept",
		"Sec-Fetch-Site",
		"Pragma",
		"Sec-Fetch-Mode",
		"User-Agent",
		"Sec-Fetch-Dest",
		"Cache-Control",
		"Accept-Language",
		"Priority",
		"Accept-Encoding",
	}

	return profile
}

func modernSafariProfile() *Fingerprint {
	return &Fingerprint{
		ClientHelloSpecFactory: safari26ClientHello,
		HeaderOrder: []string{
			"Host",
			"Connection",
			"Sec-Fetch-Dest",
			"User-Agent",
			"Accept",
			"Sec-Fetch-Site",
			"Sec-Fetch-Mode",
			"Accept-Language",
			"Priority",
			"Accept-Encoding",
		},
		PseudoHeaderOrder: []string{
			":method",
			":scheme",
			":authority",
			":path",
		},
		H2: H2Fingerprint{
			Settings: []H2Setting{
				{
					ID:  H2SettingEnablePush,
					Val: 0,
				},
				{
					ID:  H2SettingMaxConcurrentStreams,
					Val: 100,
				},
				{
					ID:  H2SettingInitialWindowSize,
					Val: 2097152,
				},
				{
					ID:  H2SettingNoRFC7540Priorities,
					Val: 1,
				},
			},
			ConnectionFlow: 10420225,
		},
	}
}

func safari26ClientHello() (*utls.ClientHelloSpec, error) {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{},
			&utls.SupportedCurvesExtension{
				Curves: []utls.CurveID{
					utls.GREASE_PLACEHOLDER,
					utls.X25519MLKEM768,
					utls.X25519,
					utls.CurveP256,
					utls.CurveP384,
					utls.CurveP521,
				},
			},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
					utls.PKCS1WithSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.PSSWithSHA384,
					utls.PSSWithSHA384, // Safari repeats this value on the wire.
					utls.PKCS1WithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA512,
					utls.PKCS1WithSHA1,
				},
			},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{
				KeyShares: []utls.KeyShare{
					{
						Group: utls.GREASE_PLACEHOLDER,
						Data:  []byte{0},
					},
					{Group: utls.X25519MLKEM768},
					{Group: utls.X25519},
				},
			},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{
				Versions: []uint16{
					utls.GREASE_PLACEHOLDER,
					utls.VersionTLS13,
					utls.VersionTLS12,
				},
			},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionZlib}},
			&utls.UtlsGREASEExtension{Body: []byte{0}},
		},
	}, nil
}
