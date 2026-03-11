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
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}
```

Built-in profiles: `Chrome()`, `Firefox()`, `Safari()`, `Edge()`, `Brave()`.

Profiles configure TLS and HTTP/2 connection-level fingerprinting (ClientHello, SETTINGS, WINDOW_UPDATE, pseudo-header order, and init PRIORITY frames). Per-request header ordering should be set via `Request.HeaderOrder` or `Fingerprint.HeaderOrder` as needed, since it varies by request type.

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
				Weight: 255,
			},
		},
	},
}
```

### Per-request header order

`HeaderOrder` and `PseudoHeaderOrder` can also be set per-request. Per-request values take priority over the Transport's fingerprint defaults.

```go
req, _ := http.NewRequest("GET", "https://example.com", nil)
req.HeaderOrder = []string{"Accept", "User-Agent", "Accept-Encoding"}
```

### Validating a fingerprint

Use `Validate()` to catch misconfigurations early:

```go
fp := &http.Fingerprint{
	PseudoHeaderOrder: []string{":method", ":path"},
}
if err := fp.Validate(); err != nil {
	log.Fatal(err) // "PseudoHeaderOrder has 2 entries, want 4"
}
```

`Validate()` checks for: missing pseudo-headers, duplicate H2 setting IDs, invalid PRIORITY stream IDs, and non-canonical header keys.

### Cloning a fingerprint

```go
fp := http.Chrome()
custom := fp.Clone()
custom.HeaderOrder = []string{"Host", "User-Agent", "Accept"}
```

### No fingerprint (standard behavior)

When `Fingerprint` is nil, the Transport behaves identically to the standard library. There are zero changes to default behavior.

## What changed from `net/http`

All modifications are additive. Existing behavior is preserved when `Fingerprint` is nil.

### New files

| File             | Purpose                                                                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `fingerprint.go` | `Fingerprint`, `H2Fingerprint`, `H2Priority`, `H2PriorityFrame`, `H2Setting`, `H2SettingID` types, `Clone()`, and `Validate()` |
| `profile.go`     | `Browser`/`Platform` enums, `Chrome()`, `Firefox()`, `Safari()`, `Edge()`, `Brave()` profile constructors                      |
| `utls.go`        | `utlsConn` wrapper, `addTLSFingerprint()`, `convertUTLSConnectionState()`                                                     |

### Modified files

| File                                | What changed                                                                                                                                                                                                       |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `transport.go`                      | `Fingerprint` field on `Transport`, `Clone()` deep-copy, `addTLS()` delegates to uTLS when fingerprinted, H2 upgrade path broadened to avoid `*tls.Conn` panic, `writeLoop` passes Transport header order fallback |
| `request.go`                        | `HeaderOrder`/`PseudoHeaderOrder` fields on `Request`, `Clone()` copies them, `write()` accepts header order fallback parameter                                                                                    |
| `header.go`                         | `writeSubsetOrdered()` method for ordered HTTP/1.1 header writing                                                                                                                                                  |
| `h2_bundle.go`                      | `fingerprint` field on `http2Transport`, fingerprint-aware SETTINGS/WINDOW_UPDATE in `newClientConn`, pseudo-header and header ordering in `http2encodeRequestHeaders`, HEADERS frame priority in `writeHeaders`   |
| `internal/httpcommon/httpcommon.go` | `PseudoHeaderOrder`/`HeaderOrder` fields on `EncodeHeadersParam`, `enumerateHeaders` rewritten to respect configured ordering                                                                                      |

### What each feature does

- **TLS fingerprinting**: Uses [uTLS](https://github.com/refraction-networking/utls) to produce browser-like ClientHello messages instead of Go's default TLS fingerprint. Configured via `Fingerprint.ClientHelloID`.
- **HTTP/1.1 header ordering**: Headers are written on the wire in the order specified by `Fingerprint.HeaderOrder` (or `Request.HeaderOrder`). Unspecified headers are appended in sorted order.
- **HTTP/2 pseudo-header ordering**: The four pseudo-headers (`:method`, `:authority`, `:scheme`, `:path`) are emitted in the order specified by `Fingerprint.PseudoHeaderOrder`. Different browsers use different orders.
- **HTTP/2 SETTINGS frame**: The SETTINGS frame sent during connection setup uses the exact settings and order from `Fingerprint.H2.Settings`.
- **HTTP/2 WINDOW_UPDATE**: The initial connection-level window update uses `Fingerprint.H2.ConnectionFlow`.
- **HTTP/2 HEADERS priority**: HEADERS frames include the priority signal from `Fingerprint.H2.HeaderPriority`.
- **HTTP/2 init PRIORITY frames**: Standalone PRIORITY frames sent during connection initialization to establish a dependency tree (part of the Akamai HTTP/2 fingerprint). Configured via `Fingerprint.H2.InitPriorityFrames`. Firefox's profile includes these by default.
- **Fingerprint validation**: `Fingerprint.Validate()` catches common misconfigurations (missing pseudo-headers, duplicate setting IDs, invalid stream IDs, non-canonical header keys).

## Testing

```bash
# Unit tests (no network required)
go test -run "TestFingerprint_|TestHeader_|TestH2SettingID" -v .

# Integration tests (requires network, hits tls.peet.ws)
go test -tags integration -run "TestIntegration_" -v .
```
