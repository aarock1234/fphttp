# fphttp

A fork of Go's `net/http` package with TLS fingerprinting, HTTP/1.1 header ordering, and HTTP/2 connection fingerprinting built in.

By building on the standard library rather than reimplementing HTTP from scratch, fphttp inherits all of Go's HTTP functionality (connection pooling, H2 flow control, GOAWAY handling, etc.) and only adds surgical modifications for fingerprinting.

## Install

```bash
go get github.com/aarock1234/fphttp
```

## Usage

fphttp is a drop-in replacement for `net/http`. Import it and set a `Fingerprint` on the `Transport`.

### Using a browser profile

```go
package main

import (
	"fmt"
	"io"

	http "github.com/aarock1234/fphttp"
)

func main() {
	client := &http.Client{
		Transport: &http.Transport{
			Fingerprint: http.Chrome(),
		},
	}

	resp, err := client.Get("https://example.com")
	if err != nil {
		panic(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}
```

Desktop profiles: `Chrome()`, `Firefox()`, `Safari()`, `Edge()`, `Brave()`.

Mobile profiles: `SafariIOS()` (iOS and iPadOS), `ChromeAndroid()`.

Profiles configure TLS and HTTP/2 connection-level fingerprinting (ClientHello, SETTINGS, WINDOW_UPDATE, pseudo-header order, and init PRIORITY frames). Per-request header ordering should be set via `Request.HeaderOrder` or `Fingerprint.HeaderOrder` as needed, since it varies by request type.

### Selecting a profile by browser and platform

`Profile(browser, platform)` resolves a `(Browser, Platform)` pair to the closest fingerprint. It is the preferred entry point for consumers that model browser choice as configuration rather than code.

```go
transport := &http.Transport{
	Fingerprint: http.Profile(http.BrowserChrome, http.PlatformMac),
}
```

On iOS and iPadOS every browser uses WebKit under Apple's App Store rules, so any browser on those platforms resolves to `SafariIOS()`. `Profile` returns `nil` if the pair has no defined mapping.

Available browsers: `BrowserChrome`, `BrowserFirefox`, `BrowserSafari`, `BrowserEdge`, `BrowserBrave`.

Available platforms: `PlatformWindows`, `PlatformMac`, `PlatformLinux`, `PlatformIOS`, `PlatformIPadOS`, `PlatformAndroid`.

### Custom fingerprint

```go
transport := &http.Transport{
	Fingerprint: &http.Fingerprint{
		ClientHelloID: utls.HelloChrome_120,
		HeaderOrder: []string{
			"Host",
			"User-Agent",
			"Accept",
			"Accept-Language",
			"Accept-Encoding",
			"Connection",
		},
		PseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		H2: http.H2Fingerprint{
			Settings: []http.H2Setting{
				{ID: http.H2SettingHeaderTableSize, Val: 65536},
				{ID: http.H2SettingEnablePush, Val: 0},
				{ID: http.H2SettingInitialWindowSize, Val: 6291456},
				{ID: http.H2SettingMaxHeaderListSize, Val: 262144},
			},
			ConnectionFlow: 15663105,
			HeaderPriority: http.H2Priority{
				Enabled: true,
				Weight:  255,
			},
		},
	},
}
```

`H2Priority.Enabled` must be `true` for the HEADERS priority to be emitted. The zero value emits no priority, matching stdlib behavior.

### Custom ClientHello

uTLS ships presets for common browser versions (`utls.HelloChrome_120`, `HelloChrome_131`, `HelloFirefox_120`, `HelloIOS_14`, etc.). When no preset matches — for example, to mimic a browser version uTLS has not published, or to reproduce a specific JA3/JA4 — provide a `ClientHelloSpec`.

```go
spec := &utls.ClientHelloSpec{
	// ... cipher suites, extensions, TLS version bounds, etc.
}
transport := &http.Transport{
	Fingerprint: &http.Fingerprint{
		ClientHelloID:   utls.HelloCustom,
		ClientHelloSpec: spec,
	},
}
```

When `ClientHelloSpec` is non-nil, set `ClientHelloID` to `utls.HelloCustom`. uTLS applies the spec via `ApplyPreset` during the handshake.

### Inheriting from `TLSClientConfig`

When a `Fingerprint` is set, the following fields of `Transport.TLSClientConfig` are passed through to the uTLS config: `ServerName`, `InsecureSkipVerify`, `RootCAs`, `NextProtos`, `MinVersion`, `MaxVersion`, `CipherSuites`, `CurvePreferences`, `PreferServerCipherSuites`, `SessionTicketsDisabled`, `DynamicRecordSizingDisabled`, `Renegotiation`, `VerifyPeerCertificate`.

Fields not currently translated: `Certificates` (client cert auth), `ClientSessionCache`, `GetClientCertificate`, `Rand`, `Time`, `KeyLogWriter`. Construct a `*utls.Config` directly and dial outside of `Transport` if you need these.

### Per-request header order

`HeaderOrder` and `PseudoHeaderOrder` can also be set per-request. Per-request values take priority over the Transport's fingerprint defaults.

```go
req, _ := http.NewRequest("GET", "https://example.com", nil)
req.HeaderOrder = []string{"Accept", "User-Agent", "Accept-Encoding"}
```

### Validating a fingerprint

Use `Validate()` to catch misconfigurations early. It returns every problem joined via `errors.Join`, not just the first.

```go
fp := &http.Fingerprint{
	PseudoHeaderOrder: []string{":method", ":path"},
	HeaderOrder:       []string{"content-type"},
}
if err := fp.Validate(); err != nil {
	log.Fatal(err)
	// fphttp: PseudoHeaderOrder missing required pseudo-header ":authority"
	// fphttp: HeaderOrder key "content-type" is not canonical, use "Content-Type"
}
```

`Validate()` checks for: missing, duplicate, or unknown pseudo-headers, duplicate H2 setting IDs, invalid PRIORITY stream IDs, and non-canonical header keys.

### Cloning a fingerprint

```go
fp := http.Chrome()
custom := fp.Clone()
custom.HeaderOrder = []string{"Host", "User-Agent", "Accept"}
```

`Clone` deep-copies slices but shares the `ClientHelloSpec` pointer. Treat a spec as immutable after use.

### No fingerprint (standard behavior)

When `Fingerprint` is nil, the Transport behaves identically to the standard library. There are zero changes to default behavior.

## What changed from `net/http`

All modifications are additive. Existing behavior is preserved when `Fingerprint` is nil.

### New files

| File             | Purpose                                                                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `fingerprint.go` | `Fingerprint`, `H2Fingerprint`, `H2Priority`, `H2PriorityFrame`, `H2Setting`, `H2SettingID` types, `Clone()`, and `Validate()` |
| `profile.go`     | `Browser`/`Platform` enums, `Profile()` resolver, and `Chrome()`, `Firefox()`, `Safari()`, `SafariIOS()`, `Edge()`, `Brave()`, `ChromeAndroid()` constructors |
| `utls.go`        | `utlsConn` wrapper, `addTLSFingerprint()`, `utlsConfigFromTLS()` translation helper, `convertUTLSConnectionState()`            |

### Modified files

| File                                | What changed                                                                                                                                                                                                       |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `transport.go`                      | `Fingerprint` field on `Transport`, `Clone()` deep-copy, `addTLS()` delegates to uTLS when fingerprinted, H2 upgrade path broadened to avoid `*tls.Conn` panic, `writeLoop` passes Transport header order fallback |
| `request.go`                        | `HeaderOrder`/`PseudoHeaderOrder` fields on `Request`, `Clone()` copies them, `write()` accepts header order fallback parameter                                                                                    |
| `header.go`                         | `writeSubsetOrdered()` method for ordered HTTP/1.1 header writing                                                                                                                                                  |
| `h2_bundle.go`                      | `fingerprint` field on `http2Transport`, fingerprint-aware SETTINGS/WINDOW_UPDATE in `newClientConn`, pseudo-header and header ordering in `http2encodeRequestHeaders`, HEADERS frame priority in `writeHeaders`   |
| `internal/httpcommon/httpcommon.go` | `PseudoHeaderOrder`/`HeaderOrder` fields on `EncodeHeadersParam`, `enumerateHeaders` rewritten to respect configured ordering                                                                                      |

### What each feature does

- **TLS fingerprinting**: Uses [uTLS](https://github.com/refraction-networking/utls) to produce browser-like ClientHello messages instead of Go's default TLS fingerprint. Configured via `Fingerprint.ClientHelloID` for named presets, or `Fingerprint.ClientHelloSpec` for fully custom handshakes.
- **HTTP/1.1 header ordering**: Headers are written on the wire in the order specified by `Fingerprint.HeaderOrder` (or `Request.HeaderOrder`). Unspecified headers are appended in sorted order.
- **HTTP/2 pseudo-header ordering**: The four pseudo-headers (`:method`, `:authority`, `:scheme`, `:path`) are emitted in the order specified by `Fingerprint.PseudoHeaderOrder`. Different browsers use different orders.
- **HTTP/2 SETTINGS frame**: The SETTINGS frame sent during connection setup uses the exact settings and order from `Fingerprint.H2.Settings`.
- **HTTP/2 WINDOW_UPDATE**: The initial connection-level window update uses `Fingerprint.H2.ConnectionFlow`.
- **HTTP/2 HEADERS priority**: HEADERS frames include the priority signal from `Fingerprint.H2.HeaderPriority` when `Enabled` is set.
- **HTTP/2 init PRIORITY frames**: Standalone PRIORITY frames sent during connection initialization to establish a dependency tree (part of the Akamai HTTP/2 fingerprint). Configured via `Fingerprint.H2.InitPriorityFrames`. Firefox's profile includes these by default.
- **Fingerprint validation**: `Fingerprint.Validate()` catches common misconfigurations and aggregates all problems via `errors.Join`.

## Testing

```bash
# Unit tests (no network required)
go test -run "TestFingerprint_|TestHeader_|TestH2SettingID|TestProfile" -v .

# Integration tests (requires network, hits tls.peet.ws)
go test -tags integration -run "TestIntegration_" -v .
```
