# fphttp

[![Go Reference](https://pkg.go.dev/badge/github.com/aarock1234/fphttp/v2.svg)](https://pkg.go.dev/github.com/aarock1234/fphttp/v2)
[![Release](https://img.shields.io/github/v/release/aarock1234/fphttp)](https://github.com/aarock1234/fphttp/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/aarock1234/fphttp)](go.mod)
[![License: BSD 3 Clause](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](LICENSE)

fphttp is Go's `net/http` with real browser fingerprints. Change one import, add a profile, and your requests look
like Chrome, Edge, Brave, Firefox, or Safari, from the TLS ClientHello to the order of the last header. Everything
else is the `net/http` you know.

It is the most accurate and complete browser TLS client for Go, with the most idiomatic API. It ships over 700
profiles, shapes every layer above TCP (TLS, HTTP/2, header order and casing, request priority, client hints,
cookies, and decoding), checks each wire against browser source or real captures, and does all of it through the
plain `Client`, `Transport`, and `Request` types.

## Why fphttp

- **It is `net/http`.** A fork synced from Go main, not a wrapper around an old copy. A `Transport` without a
  profile behaves exactly like Go's, and upstream fixes arrive through a scripted merge.
- **One field to adopt.** Set `Transport.Profile`, or call `NewClient(profile)`. Your requests, contexts, and
  middleware stay the same.
- **Over 700 profiles.** Chrome, Edge, Brave, Firefox, Firefox ESR, and Safari on Windows, macOS, Linux, Android,
  and iOS: 192 releases since January 2023. Ask for `"152"` and get the newest Chrome 152 build.
- **Every layer, per release.** The exact ClientHello of each release, including whether it offers Kyber or ML-KEM,
  plus HTTP/2 SETTINGS, window update, priority frames, pseudo header order, header order, and HTTP/1.1 casing.
- **Browser behavior, not just bytes.** `Accept`, `Sec-Fetch-*`, `Origin`, `Referer`, priority, and client hints
  follow what the request loads and which page asked for it. `Accept-CH` and `Critical-CH` are honored, cookies
  follow the browser's credentials rules, and bodies are decoded.
- **Checked against the browsers.** A verifier derives the wire of every Chrome, Edge, Brave, and Firefox major
  from browser source at its release tag and compares it with the catalog. Safari comes from real captures. A
  daily job imports new builds from official release feeds.
- **Per request control on one pool.** Change header order, casing, or priority for one request without opening
  new connections.

## Install

```sh
go get github.com/aarock1234/fphttp/v2@latest
```

Requires Go 1.27.2 or newer.

## Quick start

Import fphttp as `http`, pick a profile, and use the client like any other:

```go
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	http "github.com/aarock1234/fphttp/v2"
)

func main() {
	if err := run(); err != nil {
		slog.Error("request failed", slog.Any("error", err))
		os.Exit(1)
	}
}

func run() error {
	profile, err := http.NewProfile(http.BrowserChrome, http.PlatformWindows, http.Latest)
	if err != nil {
		return fmt.Errorf("create profile: %w", err)
	}

	client := http.NewClient(profile)
	client.Timeout = 30 * time.Second
	defer client.CloseIdleConnections()

	resp, err := client.Get("https://example.com")
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	return nil
}
```

`client.Get` sends a page load, as Chrome does when you type the URL. `NewClient` returns an ordinary
`*http.Client` with a `Transport` of its own, so set `Jar`, `Timeout`, or `CheckRedirect` on it as usual.

fphttp's types are distinct from `net/http`'s. Use its own `cookiejar`, `httptrace`, `httputil`, and `httptest`
packages alongside it.

## Choosing a profile

`NewProfile` takes a browser, a platform, and a version, and returns the profile of that release.

| Call                                                      | Selects                                                   |
| --------------------------------------------------------- | --------------------------------------------------------- |
| `NewProfile(BrowserChrome, PlatformWindows, Latest)`      | The newest Chrome on Windows                              |
| `NewProfile(BrowserChrome, PlatformMac, "152")`           | The newest build of Chrome 152 on macOS                   |
| `NewProfile(BrowserChrome, PlatformMac, "152.0.7977.85")` | That build as given; any build of a supported major works |
| `NewProfile(BrowserBrave, PlatformLinux, "1.90")`         | Brave 1.90, reported as `1.90.128`                        |
| `NewProfile(BrowserBrave, PlatformLinux, "148")`          | The Brave line built on Chromium 148, which is 1.90       |
| `NewProfile(BrowserFirefox, PlatformAndroid, "150")`      | The newest build of Firefox 150 on Android                |
| `NewProfile(BrowserFirefoxESR, PlatformWindows, "140")`   | The newest build of Firefox ESR 140                       |
| `NewProfile(BrowserSafari, PlatformIOS, "27")`            | Safari 27.0 on iPhone                                     |

A profile knows its release. `String` reports `Chrome 152.0.7977.85 on macOS` or
`Brave 1.90.128 (Chromium 148) on Linux`, and the `Browser`, `Platform`, and `Version` methods return the parts.

The `Browser`, `Platform`, and `Version` types are strings, so values from flags or configuration convert directly.
Check failures with `errors.Is`:

```go
func profileFor(browser, platform, version string) (*http.Profile, error) {
	profile, err := http.NewProfile(
		http.Browser(browser),
		http.Platform(platform),
		http.Version(version),
	)

	switch {
	case errors.Is(err, http.ErrVersionTooNew):
		slog.Warn("browser version not cataloged yet",
			slog.String("using", profile.String()),
			slog.Any("error", err),
		)

		return profile, nil

	case err != nil:
		return nil, fmt.Errorf("select browser profile: %w", err)
	}

	return profile, nil
}
```

| Error                    | Cause                                                       | Profile            |
| ------------------------ | ----------------------------------------------------------- | ------------------ |
| `ErrUnknownBrowser`      | Not one of the `Browser` constants                          | nil                |
| `ErrUnknownPlatform`     | Not one of the `Platform` constants                         | nil                |
| `ErrUnsupportedPlatform` | The browser has no profile there, such as Safari on Windows | nil                |
| `ErrUnknownVersion`      | Malformed, older than the oldest release, or left out       | nil                |
| `ErrVersionTooNew`       | Newer than the newest release                               | The newest release |

`ErrVersionTooNew` works like `strconv.ParseInt` with `ErrRange`: you get a usable value and decide whether the
difference matters.

## Full control

`NewClient` is a shortcut. A profile is one field on an ordinary `Transport`, so everything Go lets you configure
still applies:

```go
func newClient(profile *http.Profile) (*http.Client, error) {
	proxyURL, err := url.Parse("http://user:pass@proxy.example.com:8080")
	if err != nil {
		return nil, fmt.Errorf("parse proxy url: %w", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}

	transport := &http.Transport{
		Profile: profile,
		Proxy:   http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			ServerName:         "example.com",
			InsecureSkipVerify: true, // for a test server only
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   10,
	}

	client := &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   30 * time.Second,
	}

	return client, nil
}
```

`cookiejar` here is `github.com/aarock1234/fphttp/v2/cookiejar`. With a profile, HTTP/2 stays available alongside
a custom `TLSClientConfig` or dialer, as in a browser, so `ForceAttemptHTTP2` is not needed.

The profile owns the ClientHello and `TLSClientConfig` owns trust and identity:

| `TLSClientConfig` fields                                                                      | With a profile                                     |
| --------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `ServerName`, `InsecureSkipVerify`, `RootCAs`, `Certificates`, `GetClientCertificate`         | Honored as in Go                                   |
| `VerifyPeerCertificate`, `VerifyConnection`, `KeyLogWriter`, `EncryptedClientHelloConfigList` | Honored as in Go                                   |
| `SessionTicketsDisabled`                                                                      | Turns off the Transport's session cache            |
| `MinVersion`, `MaxVersion`, `CipherSuites`, `CurvePreferences`, `ClientSessionCache`          | Fail the first request; edit `Profile.TLS` instead |

The last row only conflicts while `Profile.TLS.NewHello` is set. With a nil `NewHello`, crypto/tls performs the
handshake and honors every field.

## Requests like a page

A browser sends different fields for a page, a script, an image, and a `fetch()` call. Two request fields tell
fphttp which one it is sending: `Destination`, the kind of resource, and `Initiator`, the page that asked for it.
The zero `Destination` is a page load, and a nil `Initiator` means the user started it, as when typing a URL.

```go
req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://shop.example.com/api/cart", nil)
if err != nil {
	return fmt.Errorf("create request: %w", err)
}

// A fetch() call made by the checkout page.
req.Destination = http.DestinationEmpty
req.Initiator = &url.URL{
	Scheme: "https",
	Host:   "shop.example.com",
	Path:   "/checkout",
}
req.Header.Set("Accept", "application/json")

resp, err := client.Do(req)
if err != nil {
	return fmt.Errorf("fetch cart: %w", err)
}
defer func() { _ = resp.Body.Close() }()
```

From those two fields fphttp derives `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `Origin` where the
browser sends one, `Referer`, the default `Accept`, the request priority, the subresource header order, and
whether `Client.Jar` adds cookies. A field you set wins over the generated one. The Client carries both fields to
every redirect hop.

| `Destination`                                                              | Use it for                                    | `Sec-Fetch-Mode` | Cookies from `Client.Jar`      |
| -------------------------------------------------------------------------- | --------------------------------------------- | ---------------- | ------------------------------ |
| Zero value, `DestinationDocument`                                          | A page load: typing a URL or following a link | `navigate`       | Yes                            |
| `DestinationIframe`, `DestinationFrame`                                    | A page inside a frame                         | `navigate`       | Yes                            |
| `DestinationEmpty`                                                         | `fetch()` and `XMLHttpRequest`                | `cors`           | Same origin as `Initiator`     |
| `DestinationScript`, `DestinationStyle`, `DestinationImage`                | Scripts, style sheets, and images             | `no-cors`        | Yes                            |
| `DestinationFont`, `DestinationManifest`                                   | Web fonts and app manifests                   | `cors`           | Same origin as `Initiator`     |
| `DestinationAudio`, `DestinationVideo`                                     | Media; Chromium also sends `Range: bytes=0-`  | `no-cors`        | Yes                            |
| `DestinationWorker`, `DestinationSharedWorker`, `DestinationServiceWorker` | Worker scripts                                | `same-origin`    | Same origin as `Initiator`     |

Those same origin rows treat a nil `Initiator` as a request the user started, so it gets cookies from
`Client.Jar` on any host.

Only page loads send `Sec-Fetch-User: ?1`. For a navigation started by a script, set `Sec-Fetch-User` to an empty
value. Set `Initiator` to the page's full URL rather than its origin, because `Referer` comes from it. A
`Destination` that is not one of the constants fails the request.

## Per request order and casing

These fields change one request and share the connection pool with every other request:

```go
req.HeaderOrder = []string{"Host", "User-Agent", "X-Csrf-Token", "Accept"}
req.H1HeaderCase = map[string]string{
	"X-Csrf-Token": "X-CSRF-Token",
}
req.PseudoHeaderOrder = []string{":method", ":path", ":authority", ":scheme"}
req.H2Priority = &http.H2Priority{
	Enabled:   true,
	Exclusive: true,
	Weight:    219,
}
req.H2PriorityHeader = "u=2"
```

| Setting             | Request field                                 | Falls back to                                                                      | Rule                                                                                        |
| ------------------- | --------------------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Header values       | `Header`                                      | `Profile.Header`, then generated fields                                            | A present but empty value suppresses the field                                              |
| Header order        | `HeaderOrder`                                 | `Profile.SubresourceHeaderOrder` for subresources, otherwise `Profile.HeaderOrder` | Names match ignoring case; unlisted fields follow sorted; an empty slice selects Go's order |
| HTTP/1.1 casing     | `H1HeaderCase`                                | The spelling of your own header keys, then `Profile.H1HeaderCase`                  | Merged per field, request first; HTTP/2 is always lowercase                                 |
| Pseudo header order | `PseudoHeaderOrder`                           | `Profile.PseudoHeaderOrder`                                                        | Lists all four; an empty slice selects Go's order                                           |
| HEADERS priority    | `H2Priority`                                  | The release's priority for the `Destination`                                       | `Enabled: false` sends none                                                                 |
| `Priority` field    | `Header["Priority"]`, then `H2PriorityHeader` | The release's value for the `Destination`                                          | `H2PriorityHeader` is sent on HTTP/2 only                                                   |

An empty slice here means empty but not nil; a nil field falls back. Clones and redirects keep every override.

## Customizing a profile

`NewProfile` returns a profile you own. Change its fields before a Transport first uses it, and use `Clone` to
derive variants. The Transport validates its copy, and a profile it cannot send fails every request with an error
listing each problem.

**Headers.** `Header` starts with `User-Agent` and `Accept-Language`. Every other browser field is generated per
request unless `Header` or the request sets it, and an empty value suppresses one:

```go
profile.Header.Set("Accept-Language", "de-DE,de;q=0.9,en;q=0.8")
profile.Header.Set("Dnt", "1")
profile.Header.Set("Priority", "")
```

**HTTP/1.1 casing.** Keys match ignoring case, and each value respells its key:

```go
if profile.H1HeaderCase == nil {
	profile.H1HeaderCase = make(map[string]string)
}

profile.H1HeaderCase["X-Csrf-Token"] = "X-CSRF-Token"
```

**HTTP/2.** SETTINGS go out in slice order and must include `ENABLE_PUSH = 0`:

```go
for i, setting := range profile.HTTP2.Settings {
	if setting.ID == http.H2SettingInitialWindowSize {
		profile.HTTP2.Settings[i].Val = 1 << 20
	}
}
```

Changing `HeaderPriority`, `InitialStreamID`, `InitPriorityFrames`, or `NO_RFC7540_PRIORITIES` gives every request
`HeaderPriority`, because the release's priorities for each destination no longer apply.

**TLS.** `NewHello` returns a fresh ClientHello for each connection. Bring your own, here a uTLS preset with
`utls` imported from `github.com/refraction-networking/utls`:

```go
profile.TLS.NewHello = func() (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		return nil, fmt.Errorf("build chrome 133 hello: %w", err)
	}

	return &spec, nil
}
```

It must be safe for concurrent use and leave the session ticket and `pre_shared_key` extensions empty, because the
Transport fills them from its session cache. A nil `NewHello` uses crypto/tls.

**Wire only.** A nil `Header` turns off every generated field:

```go
wireOnly := profile.Clone()
wireOnly.Header = nil
```

fphttp then sends only your headers, including your own `User-Agent`, with the profile's TLS, HTTP/2, order, and
casing. A `Profile` literal behaves the same way, since it has no release to generate fields from.

## How it behaves

| Topic              | Behavior                                                                                                                                                                                                                   |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No profile         | A `Transport` with a nil `Profile` behaves exactly like Go's.                                                                                                                                                              |
| First use          | The Transport copies its `Profile` on first use and ignores later edits. Use a new `Transport` or `Transport.Clone` to apply them.                                                                                         |
| TLS                | `Profile.TLS` owns the ClientHello; `TLSClientConfig` owns trust and identity. Conflicting fields fail the first request.                                                                                                  |
| Session resumption | Each `Transport` resumes TLS sessions from a cache of its own. `TLSClientConfig.SessionTicketsDisabled` turns it off. Connections configured with an `EncryptedClientHelloConfigList` never resume.                        |
| Protocols          | HTTP/1.1 and HTTP/2. A profile with HTTP/3 in `Protocols`, or with an `h2` entry in `TLSNextProto`, fails every request.                                                                                                   |
| Go's defaults      | With a profile, Go never adds its own `User-Agent` or `Accept-Encoding: gzip`.                                                                                                                                             |
| Client hints       | Chromium profiles send `Sec-CH-UA`, `Sec-CH-UA-Mobile`, and `Sec-CH-UA-Platform` to secure origins. Other hints follow `Accept-CH` from page loads, remembered per `Transport` and origin. `Clear-Site-Data` forgets them. |
| Critical-CH        | The Client restarts a page load when `Critical-CH` names a hint it lacked: once per origin, at most ten times per call, within the same deadline. GET and HEAD only; bodies need `GetBody`.                                |
| Referer            | Built from `Initiator` and the newest `Referrer-Policy` on the redirect chain, `strict-origin-when-cross-origin` by default. A `Referer` you set is kept.                                                                  |
| Cookies            | `Client.Jar` works as usual, within the credentials rules of the `Destination`. An empty `Cookie` field declines jar cookies on any request that is not a navigation.                                                      |
| Credentials        | `Authorization`, `Cookie`, and the other credential fields in `Profile.Header` are sent only while redirects stay on the first host or its subdomains.                                                                     |
| Decompression      | When the profile supplied `Accept-Encoding`, bodies are decoded as you read them: gzip, deflate, br, zstd, and stacked codings. Your own `Accept-Encoding` gets the raw body. `DisableCompression` turns decoding off.     |
| Proxies            | HTTP, HTTPS, and SOCKS5 work as in Go. CONNECT carries the profile's `User-Agent`, and Chromium profiles send `Proxy-Connection: keep-alive` as Chrome does. The TLS session with an HTTPS proxy uses crypto/tls.          |
| Custom dialers     | `DialTLSContext` owns TLS, so the profile's ClientHello does not apply there. HTTP/2 and header settings still do.                                                                                                         |
| TCP                | fphttp shapes what your process sends. TCP options, window sizes, and TTL follow your host or proxy.                                                                                                                       |

## Supported browsers

| Browser     | Windows                 | macOS                   | Linux                   | Android      | iOS  |
| ----------- | ----------------------- | ----------------------- | ----------------------- | ------------ | ---- |
| Chrome      | 108 to 156              | 109 to 156              | 109 to 155              | 110 to 156   |      |
| Edge        | 119 to 155              | 119 to 155              | 119 to 155              | 140 to 155   |      |
| Brave       | 1.46 to 1.97            | 1.46 to 1.97            | 1.46 to 1.97            | 1.56 to 1.97 |      |
| Firefox     | 108 to 158              | 108 to 158              | 108 to 158              | 126 to 158   |      |
| Firefox ESR | 102, 115, 128, 140, 153 | 102, 115, 128, 140, 153 | 102, 115, 128, 140, 153 |              |      |
| Safari      |                         | 26.0, 27.0              |                         |              | 27.0 |

As of October 2026 that is 707 profiles for 192 releases, built from 31 distinct wire configurations. Each version
resolves to the newest build of its release line, and the daily sync picks up new builds as browsers publish them.

- Brave 1.46 to 1.97 are built on Chromium 108 to 155, and `NewProfile` accepts either number.
- Edge before 119 on desktop and before 140 on Android, Chrome 109 on Android, and Brave 1.46 to 1.52 on Android
  are left out, because their `User-Agent` cannot be reproduced exactly.
- iPadOS, and browsers other than Safari on iOS, return `ErrUnsupportedPlatform`. Safari covers captured releases
  only and is never extrapolated.
- Firefox 131 and older, ESR 102, and ESR 115 allowed HTTP/2 server push by default. fphttp cannot accept push, so
  those profiles send what Firefox sends with push turned off: `ENABLE_PUSH = 0` and `MAX_CONCURRENT_STREAMS = 0`.

## Upgrading from v1

| v1                                                                                                 | v2                                                                               |
| -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `github.com/aarock1234/fphttp`                                                                     | `github.com/aarock1234/fphttp/v2`                                                |
| `Transport.Fingerprint`                                                                            | `Transport.Profile`                                                              |
| `Chrome()`, `Chrome148()`, `ChromeMac()`, `Firefox120()`, `Safari27()`, and the other constructors | `NewProfile(browser, platform, version)`                                         |
| `Profile(browser, platform)`                                                                       | `NewProfile(browser, platform, Latest)`                                          |
| `Chrome148Fetch()`, `Safari27Fetch()`, and the other fetch constructors                            | `Request.Destination = DestinationEmpty` with `Request.Initiator`                |
| `browser.Resolve(browser.Selector{...})`                                                           | `NewProfile`, with errors checked by `errors.Is`                                 |
| `browser.New(browser.Config{...})`                                                                 | `NewClient(profile)`, or a `Client` and `Transport` you build                    |
| `Client.DoWithOptions` with a `RequestContext`                                                     | `Client.Do` with `Request.Destination` and `Request.Initiator`                   |
| `RequestContext.UserActivation`                                                                    | Page loads send `Sec-Fetch-User: ?1`; set it empty to drop it                    |
| `RequestContext.Languages`, `RequestContext.AcceptLanguage`                                        | `Accept-Language` in `Profile.Header`                                            |
| `Config.DefaultHeaders`                                                                            | `Profile.Header`                                                                 |
| `Config.DisableHeaders`                                                                            | `Profile.Header = nil`                                                           |
| `Config.Fingerprint`                                                                               | Edit `Profile.TLS`, `Profile.HTTP2`, and the orders                              |
| `Config.Timeout`, `Config.Jar`, `Config.CheckRedirect`                                             | The same fields on `Client`                                                      |
| `Config.CookiePolicy`                                                                              | Any `CookieJar` in `Client.Jar`                                                  |
| `Config.DisableDecompression`                                                                      | `Transport.DisableCompression`                                                   |
| `Client.ClearClientHints`                                                                          | A new `Transport`; hints are remembered per `Transport`                          |
| `RequestOptions.AllowReplay`                                                                       | Removed; `Critical-CH` restarts GET and HEAD only                                |
| `Fingerprint.ClientHelloID`, `ClientHelloSpec`, `ClientHelloSpecFactory`                           | `Profile.TLS.NewHello`                                                           |
| `Fingerprint.ClientSessionCache`                                                                   | Automatic per `Transport`; `TLSClientConfig.SessionTicketsDisabled` turns it off |
| `Fingerprint.GetClientCertificate`                                                                 | `TLSClientConfig.GetClientCertificate`                                           |
| `Fingerprint.H2`, `H2Fingerprint`                                                                  | `Profile.HTTP2`, `HTTP2Profile`                                                  |
| `H2Fingerprint.SettingsFactory`                                                                    | Removed                                                                          |
| `Fingerprint.Clone`, `Fingerprint.Validate`                                                        | `Profile.Clone`; validation runs when a Transport first uses the profile         |

## Maintaining

Production sources track [Go main at `e60b4c3`](https://github.com/golang/go/tree/e60b4c37fa344513cdecfffe6efc3ca48c4a6cb2/src/net/http),
recorded in `.stdlib-version`. TLS uses upstream uTLS pinned at
[`ff1b50f`](https://github.com/refraction-networking/utls/tree/ff1b50fbbe9a), with no separate fork. Browser
knowledge lives in `internal/catalog` as Go source: a generated release table plus wire configurations written by
hand from browser source and captures.

```sh
go run ./internal/cmd/syncstdlib -ref master
go generate ./internal/catalog
go run ./internal/cmd/verifyprofiles
go build ./...
go build -tags nethttpomithttp2 ./...
go run ./internal/cmd/checksource
git diff --check
```

| Tool                          | Purpose                                                                                                        |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `internal/cmd/syncstdlib`     | Merges a Go revision into the fork and stops on conflicts                                                      |
| `internal/cmd/syncprofiles`   | Regenerates `internal/catalog/builds_gen.go` from official release feeds; run it with `go generate`            |
| `internal/cmd/verifyprofiles` | Derives each major's wire from browser source, compares it with the catalog, and reports releases with no wire |
| `internal/cmd/observe`        | Sends requests to `tls.but.sh` and records what the server saw; `-catalog` lists every supported release       |
| `internal/cmd/checksource`    | Checks formatting and vets production sources                                                                  |

The `sync-profiles` workflow runs daily. It regenerates the release table, runs `verifyprofiles`, builds, checks
the source, and opens a pull request. A new major with no wire in `internal/catalog` fails verification until one
is added. The `sync-stdlib` workflow runs on demand for a new Go revision, and releases are cut by hand with
`release.yaml`.

Observations describe fphttp's own traffic, not a browser capture. `httptest/server.go` stays on Go 1.26.5 because
newer code needs runtime support.

## License

Go's copied sources keep their [BSD license](LICENSE).
