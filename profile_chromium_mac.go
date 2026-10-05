package http

import (
	utls "github.com/refraction-networking/utls"
)

// ChromeMac models the captured Chrome 154 macOS HTTP/2 settings and navigation
// header order using the supported Chrome 133 TLS baseline. It does not reproduce
// Chrome 154's trust-anchor extension or ML-DSA signature algorithms.
func ChromeMac() *Fingerprint {
	profile := Chrome154MacHTTP2()
	profile.ClientHelloID = utls.HelloChrome_133

	return profile
}

// ChromeMacFetch uses the captured macOS fetch order and priority with the same
// supported TLS baseline as ChromeMac. It is not a complete Chrome 154 TLS match.
func ChromeMacFetch() *Fingerprint {
	profile := Chrome154MacHTTP2Fetch()
	profile.ClientHelloID = utls.HelloChrome_133

	return profile
}

// Chrome154MacHTTP2 models the captured Chrome 154 macOS HTTP/2 navigation.
// It leaves TLS to crypto/tls or the caller's DialTLSContext. The current uTLS
// version cannot reproduce this capture's complete TLS capabilities safely.
func Chrome154MacHTTP2() *Fingerprint {
	profile := chromiumProfile(utls.ClientHelloID{})
	profile.HeaderOrder = []string{
		"Host",
		"Connection",
		"Accept-Language",
		"Upgrade-Insecure-Requests",
		"User-Agent",
		"Accept",
		"Sec-Ch-Ua",
		"Sec-Ch-Ua-Mobile",
		"Sec-Ch-Ua-Platform",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Sec-Fetch-User",
		"Sec-Fetch-Dest",
		"Accept-Encoding",
		"Priority",
	}

	return profile
}

// Chrome154MacHTTP2Fetch models the captured macOS fetch order and priority.
// Like Chrome154MacHTTP2, it does not select a browser TLS ClientHello.
func Chrome154MacHTTP2Fetch() *Fingerprint {
	profile := Chrome154MacHTTP2()
	profile.HeaderOrder = []string{
		"Host",
		"Connection",
		"Pragma",
		"Cache-Control",
		"Sec-Ch-Ua-Platform",
		"Accept-Language",
		"Sec-Ch-Ua",
		"User-Agent",
		"Sec-Ch-Ua-Mobile",
		"Accept",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Sec-Fetch-Dest",
		"Accept-Encoding",
		"Priority",
	}
	profile.H2.HeaderPriority.Weight = 219

	return profile
}
