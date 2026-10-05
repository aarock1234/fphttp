# fphttp

fphttp is a fork of Go's `net/http` with browser TLS profiles, header ordering, and HTTP/2 fingerprint controls. It keeps Go's client and server APIs, connection pooling, and request cancellation.

Requires Go 1.27.1 or newer.

## Install

```sh
go get github.com/aarock1234/fphttp@v1.3.0
```

## Use a browser profile

Import fphttp as `http` and set a profile on your transport. Reuse the client for subsequent requests.

```go
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	http "github.com/aarock1234/fphttp"
)

func main() {
	if err := run(); err != nil {
		slog.Error("request failed", slog.Any("error", err))
		os.Exit(1)
	}
}

func run() error {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Fingerprint = http.Chrome()
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	resp, err := client.Get("https://example.com")
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected response status: %s", resp.Status)
	}
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	return nil
}
```

Read successful response bodies to EOF and close them so connections can be reused. Use request contexts and client deadlines to bound request lifetime.

Profiles control protocol settings and header order. Supply your own User-Agent, client hints, cookies, and other browser headers. Only advertise encodings your application can decode; fphttp automatically decodes gzip.

fphttp's request, response, and transport types are distinct from those in `net/http`.

## Profiles

Choose a constructor directly or select a browser and platform:

```go
profile := http.Profile(http.BrowserChrome, http.PlatformMac)
```

| Constructors | Baseline |
| --- | --- |
| `Chrome()`, `Chrome148()`, `Chrome148Fetch()` | Windows Chrome 148 navigation and fetch |
| `Chrome120()`, `Chrome131()`, `Chrome133()` | Versioned uTLS Chrome presets |
| `ChromeMac()`, `ChromeMacFetch()` | Captured Mac Chrome HTTP/2 behavior with supported Chrome 133 TLS |
| `Chrome154MacHTTP2()`, `Chrome154MacHTTP2Fetch()` | Mac Chrome 154 HTTP/2 behavior; TLS stays with your dialer or `crypto/tls` |
| `Safari()`, `Safari27()`, `Safari27Fetch()` | Mac Safari 27 navigation and fetch |
| `Safari26()` | Published Mac Safari 26.0.1 baseline |
| `SafariIOS()`, `SafariIOS27()`, `SafariIOS27Fetch()` | iPhone Safari 27.0.1 navigation and fetch |
| `Firefox()`, `Firefox144()` | Published Firefox 144 baseline |
| `Firefox120()` | Historical Firefox 120 TLS and HTTP/2 priority tree |
| `Edge()`, `Brave()`, `ChromeAndroid()` | Shared Chromium baseline, without separate browser captures |

`Profile` returns `nil` for unsupported combinations. iOS and iPadOS selections use the captured WebKit profile. Browser builds using another engine need a custom profile.

Mac Chrome 154 advertises ML-DSA signatures and a trust-anchor extension that uTLS 1.8.2 does not implement. The Mac Chrome profiles document this TLS limitation. Windows Chrome 148's TLS parameters match uTLS's Chrome 133 preset.

Chromium shuffles TLS extensions. Browsers also generate fresh GREASE values and key material, so profiles do not replay fixed JA3 strings. Header order follows the captures; header values and other browser behavior remain your application's responsibility.

The published baselines come from [Safari 26.0.1](https://github.com/lexiforest/curl-impersonate/blob/3f5d207ba9101a779a65ced1288c32aeec762d66/tests/signatures/safari_26.0.1_macOS.yaml) and [Firefox 144](https://github.com/lexiforest/curl-impersonate/blob/3f5d207ba9101a779a65ced1288c32aeec762d66/tests/signatures/firefox_144.0.0_linux.yaml) captures. The Firefox capture identifies macOS despite its filename.

## Request overrides

Change header order or priority for individual requests while keeping one connection pool:

```go
req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
if err != nil {
	return err
}

fetch := http.Chrome148Fetch()
req.HeaderOrder = fetch.HeaderOrder
req.H2Priority = new(fetch.H2.HeaderPriority)
req.Header.Set("Accept", "application/json")
req.Header.Set("Priority", "u=1, i")
```

Non-nil request orders override the transport profile. An empty slice selects Go's default order. Unlisted regular headers follow in sorted order. Clones and redirects preserve these overrides.

`H2Priority.Enabled` controls whether a request sends legacy HEADERS priority. Set it to `true` for custom priorities. `Weight` is the wire value, from 0 to 255, representing effective weights 1 to 256. A request priority with `Enabled: false` suppresses the signal.

## Custom profiles

Clone a profile before changing it, then validate your configuration:

```go
profile := http.Chrome148().Clone()
profile.HeaderOrder = []string{
	"Host",
	"User-Agent",
	"Accept",
	"Accept-Encoding",
}

if err := profile.Validate(); err != nil {
	return err
}
```

Keep profiles and TLS configuration immutable after the transport starts using them. A nil fingerprint uses Go's TLS and HTTP defaults.

`Fingerprint.H2` controls ordered SETTINGS, the connection-window increment, the first stream ID, and optional priority frames. Custom SETTINGS must include `ENABLE_PUSH = 0`. `ConnectionFlow` adds to the initial 65,535-byte window. Zero uses Go's increment. `InitialStreamID` must be an odd 31-bit value; zero uses stream 1.

Header names must be canonical and unique. A custom pseudo-header order must contain `:method`, `:authority`, `:scheme`, and `:path` exactly once. Setting `NO_RFC7540_PRIORITIES = 1` cannot be combined with legacy priority signals. External HTTP/2 transports cannot be combined with a fingerprint.

For TLS, choose a uTLS `ClientHelloID` or provide a custom `ClientHelloSpec` or `ClientHelloSpecFactory`. A zero `ClientHelloID` keeps `crypto/tls`. Custom specs cannot be combined with a named preset.

Templates copy supported extensions for each connection. Stateful or third-party extensions require a factory that returns fresh, independently owned state. Factories may be called concurrently.

The uTLS integration honors supported TLS restrictions, roots, verification callbacks, and static client certificates. Use `Fingerprint.GetClientCertificate` for dynamic certificate selection and `Fingerprint.ClientSessionCache` for a concurrent uTLS session cache. A nil cache disables resumption. Resumption also needs a preset with a compatible PSK extension.

HTTPS proxies use a separate TLS handshake before the CONNECT tunnel. The origin profile applies inside that tunnel. ALPN advertises only protocols the transport can use.

`Response.TLS` contains converted uTLS metadata. It cannot expose the negotiated curve or support `ExportKeyingMaterial`. Use `crypto/tls` or retain your own uTLS connection if you need those APIs.

## TCP and HTTP/3

Selecting a profile does not change your operating system's TCP stack. TCP options, receive windows, and TTL depend on the host and network path. Match the host or proxy egress environment when you need its TCP fingerprint.

fphttp has no built-in HTTP/3 client. Go's HTTP/3 integration hooks do not supply a QUIC transport or browser HTTP/3 fingerprinting.

## Maintain the fork

The production HTTP sources follow [Go main at `a90c4a7`](https://github.com/golang/go/tree/a90c4a7a586c70f0de61f5507d5c347702432e39/src/net/http). `.stdlib-version` records the exact revision. Browser TLS uses [uTLS 1.8.2](https://github.com/refraction-networking/utls/tree/v1.8.2).

Sync a new Go revision and check the resulting code:

```sh
go run ./internal/cmd/syncstdlib -ref master
go build ./...
go run ./internal/cmd/checksource
git diff --check
```

The sync stages three-way merges before writing checkout files and stops on conflicts. A filesystem write failure can leave a partial diff. `checksource` checks formatting and vets production code.

The standalone fork uses local copies of private HTTP helpers, a bounded MIME parser, and owned HTTP/2 writer-result channels. Runtime aliases are removed. The local `GODEBUG` adapter reads environment settings without runtime metrics or module defaults.

`httptest/server.go` and its certificate helper retain Go 1.26.5 because the newer code needs runtime support. Private HTTP/3 sources and existing test files are excluded from the production sync.

Go's copied sources retain their BSD license in [LICENSE](LICENSE).
