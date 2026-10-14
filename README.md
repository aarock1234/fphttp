# fphttp

fphttp is a fork of Go's `net/http` with browser TLS profiles, header ordering, and HTTP/2 fingerprint controls. It keeps Go's client and server APIs, connection pooling, and request cancellation.

Requires Go 1.27.2 or newer.

## Install

```sh
go get github.com/aarock1234/fphttp@main
```

## Versioned browser client

The additive `browser` package resolves published product versions separately
from their rendering engine, platform, device, channel, and configuration variant.
It owns identity headers, transport pools, response decoding, redirects, and
negotiated UA client hints. The low-level APIs below remain available.

```go
profile, err := browser.Resolve(browser.Selector{
	Browser:  http.BrowserChrome,
	Platform: http.PlatformWindows,
	Version:  "152",
})
if err != nil {
	return err
}

client, err := browser.New(browser.Config{
	Profile: profile,
	Timeout: 20 * time.Second,
})
if err != nil {
	return err
}
defer client.CloseIdleConnections()

req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
if err != nil {
	return err
}
resp, err := client.DoWithOptions(req, browser.RequestOptions{
	Context: &browser.RequestContext{
		Kind:           browser.Navigation,
		UserActivation: true,
		Languages:      []string{"en-US", "en"},
	},
})
if err != nil {
	return err
}
defer func() { _ = resp.Body.Close() }()
```

Import `github.com/aarock1234/fphttp/browser` alongside fphttp. `Do` supplies
basic identity headers only. `DoWithOptions` accepts explicit navigation, fetch,
or resource context; it does not infer browser activity from a URL. Supply an
initiating origin for fetches and resources. Locale, device architecture, model,
and OS hint values come from caller metadata rather than the running machine.
Use `AcceptLanguage` for exact Apple language formatting.

`Resolve` accepts an exact version or numeric prefix such as `"152"`. It selects
the newest matching published build. `Available` reports whether an entry has
a usable fingerprint; unavailable selections return `ErrUnavailable`.
Descriptors include configuration sources and implementation notes.

Request headers override generated values. A present nil or empty field
suppresses generation; deleting it restores the default. `DefaultHeaders`
provides client-wide overrides and `DisableHeaders` disables generation.
`Config.Fingerprint` overrides wire behavior while retaining the selected identity;
use the low-level transport for unrestricted uTLS configuration.

`ResolveIdentity` selects known published identity metadata without requiring a
catalog wire definition. Its `Fingerprint()` is nil; provide a deliberate
`Config.Fingerprint` override when using that identity in a client. Unknown
product builds remain errors.

### Supported browsers

Profiles support TLS hellos, HTTP/1.1 header controls, HTTP/2 settings and
priorities, browser identity headers, and contextual client hints.

| Browser | Platforms | Available configurations |
| --- | --- | ---: |
| Chrome | Windows, macOS, Linux, Android | 247 source defaults + 247 H2 SETTINGS GREASE variants = **494** |
| Firefox | Windows, macOS, Linux, Android | 114 source defaults + 81 push-disabled variants = **195** |
| Brave | Windows, macOS, Linux, Android | **192** product configurations with pinned Chromium engines |
| Edge | Windows, macOS, Linux, Android | **1,144** Chromium-based configurations (`chromium-source-assumption`) |
| Safari | macOS, iOS | **3** capture-based configurations (`existing-capture-family`) |

The October 13, 2026 catalog contains **6,288 release/platform/channel entries**
from releases published since January 2023, plus **1,475 configuration variants**:
247 Chrome GREASE + 81 Firefox push-disabled + 1,144 Edge + 3 Safari.
That yields **7,763 catalog entries**, including **2,028 available configurations**.
Platform entries carry their own identity and release metadata; multiple entries
can share the same TLS and H2 configuration. Other published builds are listed
for identity selection with a custom fingerprint.

Client hints are stored in memory per profile and origin for the client's
lifetime. Explicit secure navigations can learn `Accept-CH`; eligible
`Critical-CH` responses restart the original navigation with one shared
deadline, a bounded count, and at most one restart per origin. GET and HEAD are
eligible by default; other methods require `AllowReplay`, and bodies require
`GetBody`. Unavailable metadata and suppressed hints never trigger a restart.
Recognized `Clear-Site-Data` clears applicable state before processing opt-ins.
Call `ClearClientHints` when clearing externally managed cookies or site state.

Automatic cookie application and storage respect contextual credentials mode.
An empty Cookie field suppresses automatic application. `Jar` appends scoped
cookies after nonempty explicit values, following fphttp's ordinary rules;
`CookiePolicy` owns custom merging, serialization, and response extraction.

The decoder supports gzip, zlib or raw deflate, Brotli, and Zstandard, including
stacked encodings. Advertising an encoding is version and destination aware.
Returned response bodies belong to the caller. The operation deadline remains
active while the body is read and is released on EOF, a read error, or Close.

## Low-level browser profiles

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

The legacy Mac Chrome constructors retain their original Chrome 133 TLS baseline.
The versioned catalog constructs newer hellos with the pinned upstream uTLS
capabilities, including ML-DSA and trust-anchor advertisement where reviewed
source enables them. Use the versioned catalog to select newer browser builds.

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
req.H2PriorityHeader = "u=1, i"
```

Non-nil request orders override the transport profile. An empty slice selects Go's default order. Unlisted regular headers follow in sorted order. Clones and redirects preserve these overrides.

`H2Priority.Enabled` controls whether a request sends legacy HEADERS priority. Set it to `true` for custom priorities. `Weight` is the wire value, from 0 to 255, representing effective weights 1 to 256. A request priority with `Enabled: false` suppresses the signal.

`H2PriorityHeader` supplies an extensible Priority field only over H2. An
explicit `Header["Priority"]`, including a suppression marker, takes precedence.
The generated field is last unless an explicit order lists its position. The
browser client generates it only for reviewed builds and request contexts.

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

`H2.SettingsFactory` supplies fresh ordered settings once per connection and
cannot accompany static `Settings`. The returned settings are validated before
the connection is used. Factories must be concurrency safe. `H1HeaderCase` maps
canonical field names to their HTTP/1.1 spelling, including framing fields and
trailers; it does not affect H2 lowercase encoding. Request-level maps override
transport maps, and an empty map disables spelling overrides.

Header names must be canonical and unique. A custom pseudo-header order must contain `:method`, `:authority`, `:scheme`, and `:path` exactly once. Setting `NO_RFC7540_PRIORITIES = 1` cannot be combined with legacy priority signals. External HTTP/2 transports cannot be combined with a fingerprint.

For TLS, choose a uTLS `ClientHelloID` or provide a custom `ClientHelloSpec` or `ClientHelloSpecFactory`. A zero `ClientHelloID` keeps `crypto/tls`. Custom specs cannot be combined with a named preset.

Templates copy supported extensions for each connection. Stateful or third-party extensions require a factory that returns fresh, independently owned state. Factories may be called concurrently.

The uTLS integration honors supported TLS restrictions, roots, verification callbacks, and static client certificates. Use `Fingerprint.GetClientCertificate` for dynamic certificate selection and `Fingerprint.ClientSessionCache` for a concurrent uTLS session cache. A nil cache disables resumption. Resumption also needs a preset with a compatible PSK extension.

HTTPS proxies use a separate TLS handshake before the CONNECT tunnel. The origin profile applies inside that tunnel. ALPN advertises only protocols the transport can use.

`Response.TLS` contains converted uTLS metadata, including the negotiated curve,
HelloRetryRequest status, and local certificate. `ExportKeyingMaterial` is not
available through the converted state; retain your own uTLS connection if needed.

## TCP and HTTP/3

Selecting a profile does not change your operating system's TCP stack. TCP options, receive windows, and TTL depend on the host and network path. Match the host or proxy egress environment when you need its TCP fingerprint.

HTTP/3 is a future transport option. [quic-go](https://quic-go.net/docs/http3/client/)
provides an H3 client; [uQUIC](https://github.com/refraction-networking/uquic)
adds QUIC packet and hello controls. Integration would cover QUIC parameters,
H3 SETTINGS, QPACK, priorities, discovery, and fallback.

## Maintain the fork

The production HTTP sources follow [Go main at `e60b4c3`](https://github.com/golang/go/tree/e60b4c37fa344513cdecfffe6efc3ca48c4a6cb2/src/net/http).
`.stdlib-version` records the exact revision. Browser TLS uses the existing
upstream uTLS module, pinned at [commit `ff1b50f`](https://github.com/refraction-networking/utls/tree/ff1b50fbbe9a).
Profiles live in fphttp; no separate uTLS fork or automatic dependency updater
is introduced.

Sync a new Go revision and check the resulting code:

```sh
go run ./internal/cmd/syncstdlib -ref master
go build ./...
go run ./internal/cmd/checksource
git diff --check
```

The sync stages three-way merges before writing checkout files and stops on conflicts. A filesystem write failure can leave a partial diff. `checksource` checks formatting and vets production code.

`internal/cmd/syncprofiles` imports primary release metadata and reviewed source
defaults into the checked-in catalog. It is a manually invoked catalog tool;
it does not update uTLS. Review generated source mappings and coverage before
shipping a catalog change. `internal/cmd/observe` makes bounded live requests to
`https://h1.tls.but.sh/api/network` and `https://h2.tls.but.sh/api/network`, emitting
the selected descriptor and server observations. Protocol restrictions are
explicitly reported because they also alter the offered hello. These captures
describe fphttp traffic; they are not evidence of a real browser capture.

The standalone fork uses local copies of private HTTP helpers, a bounded MIME parser, and owned HTTP/2 writer-result channels. Runtime aliases are removed. The local `GODEBUG` adapter reads environment settings without runtime metrics or module defaults.

`httptest/server.go` and its certificate helper retain Go 1.26.5 because the newer code needs runtime support. Private HTTP/3 sources and existing test files are excluded from the production sync.

Go's copied sources retain their BSD license in [LICENSE](LICENSE).
