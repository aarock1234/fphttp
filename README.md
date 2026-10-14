# fphttp

[![Go Reference](https://pkg.go.dev/badge/github.com/aarock1234/fphttp/v2.svg)](https://pkg.go.dev/github.com/aarock1234/fphttp/v2)
[![Release](https://img.shields.io/github/v/release/aarock1234/fphttp)](https://github.com/aarock1234/fphttp/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/aarock1234/fphttp)](go.mod)
[![License: BSD 3 Clause](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](LICENSE)

fphttp is Go's `net/http` with real browser fingerprints. Change the import, pick a browser, and your requests look
like Chrome, Edge, Brave, Firefox, or Safari, from the TLS handshake to the order of the last header.

It is the most accurate and complete browser TLS client for Go, and it needs nothing beyond the `net/http` API you
already use.

- A fork of `net/http` kept in sync with Go. Without a profile it behaves exactly like the standard library.
- 3,589 stable browser builds released since January 2023, on Windows, macOS, Linux, Android, and iOS.
- Every layer matches the browser: TLS ClientHello, HTTP/2 settings and priorities, header order and casing, client
  hints, cookies, and decompression.
- Each release is checked against browser source or real captures, and new builds are imported daily.

## Install

```sh
go get github.com/aarock1234/fphttp/v2@latest
```

Requires Go 1.27.2 or newer.

## Quick start

```go
package main

import (
	"fmt"
	"io"
	"log"

	http "github.com/aarock1234/fphttp/v2"
)

func main() {
	profile, err := http.NewProfile(http.BrowserChrome, http.PlatformWindows, http.Latest)
	if err != nil {
		log.Fatal(err)
	}

	client := http.NewClient(profile)

	resp, err := client.Get("https://example.com")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(body))
}
```

`NewClient` returns an ordinary `*http.Client`, so `Jar`, `Timeout`, and `CheckRedirect` work as usual. Use
fphttp's own `cookiejar`, `httptrace`, `httputil`, and `httptest` packages alongside it.

## Choosing a profile

| Call                                                      | Profile                                   |
| --------------------------------------------------------- | ----------------------------------------- |
| `NewProfile(BrowserChrome, PlatformWindows, Latest)`      | Newest Chrome on Windows                  |
| `NewProfile(BrowserChrome, PlatformMac, "152")`           | Newest build of Chrome 152 on macOS       |
| `NewProfile(BrowserChrome, PlatformMac, "152.0.7977.50")` | That exact Chrome build                   |
| `NewProfile(BrowserBrave, PlatformWindows, "1.90")`       | Brave 1.90, which also answers to `"148"` |
| `NewProfile(BrowserSafari, PlatformIOS, "27")`            | Safari 27 on iPhone                       |

The `Browser`, `Platform`, and `Version` types are strings, so values from flags or config convert directly. A
version newer than the catalog returns the newest profile along with `ErrVersionTooNew`, so you can decide whether
that matters:

```go
profile, err := http.NewProfile(http.BrowserChrome, http.PlatformWindows, "999")
if errors.Is(err, http.ErrVersionTooNew) {
	slog.Warn("using the newest cataloged release", slog.String("profile", profile.String()))
} else if err != nil {
	return err
}
```

Other failures are `ErrUnknownBrowser`, `ErrUnknownPlatform`, `ErrUnsupportedPlatform`, and `ErrUnknownVersion`.

## Using your own Transport

A profile is one field on a regular `Transport`, so every other setting still works:

```go
transport := &http.Transport{
	Profile:             profile,
	Proxy:               http.ProxyURL(proxyURL),
	TLSHandshakeTimeout: 10 * time.Second,
	IdleConnTimeout:     90 * time.Second,
}

client := &http.Client{
	Transport: transport,
	Timeout:   30 * time.Second,
}
```

The profile owns the ClientHello. `TLSClientConfig` still controls trust and identity, such as `ServerName`,
`RootCAs`, `InsecureSkipVerify`, and client certificates. Fields that would change the ClientHello fail the first
request: `MinVersion`, `MaxVersion`, `CipherSuites`, `CurvePreferences`, and `ClientSessionCache`. Edit
`Profile.TLS` instead.

## Requests like a browser

Browsers send different headers for a page, a script, an image, or a `fetch()` call. Tell fphttp which one you are
making with `Destination`, and which page made it with `Initiator`:

```go
req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://shop.example.com/api/cart", nil)
if err != nil {
	return err
}

req.Destination = http.DestinationEmpty
req.Initiator = &url.URL{
	Scheme: "https",
	Host:   "shop.example.com",
	Path:   "/checkout",
}
```

From these, fphttp fills in `Sec-Fetch-*`, `Origin`, `Referer`, `Accept`, request priority, and header order, and
applies the browser's cookie rules. Headers you set yourself always win. The zero `Destination` is a page load.

| `Destination`                                               | Used for                                     |
| ----------------------------------------------------------- | -------------------------------------------- |
| Zero value, `DestinationDocument`                           | Page loads                                   |
| `DestinationEmpty`                                          | `fetch()` and `XMLHttpRequest`               |
| `DestinationScript`, `DestinationStyle`, `DestinationImage` | Page resources                               |
| `DestinationIframe`                                         | Pages inside frames                          |
| `DestinationWebSocket`                                      | WebSocket handshakes, detected automatically |

Header order and HTTP/1.1 casing can also be set per request, without opening new connections:

```go
req.HeaderOrder = []string{"Host", "User-Agent", "X-Csrf-Token", "Accept"}
req.H1HeaderCase = map[string]string{
	"X-Csrf-Token": "X-CSRF-Token",
}
```

## Customizing a profile

`NewProfile` returns a profile you own. Edit it before its first use, or call `Clone` to make variants:

```go
profile.Header.Set("Accept-Language", "de-DE,de;q=0.9")

for i, setting := range profile.HTTP2.Settings {
	if setting.ID == http.H2SettingInitialWindowSize {
		profile.HTTP2.Settings[i].Val = 1 << 20
	}
}
```

`Profile.TLS.NewHello` returns the ClientHello for each connection as a
[uTLS](https://github.com/refraction-networking/utls) spec, so you can bring your own. Setting `Profile.Header` to
nil keeps the TLS and HTTP/2 fingerprint but sends only the headers you set.

## Good to know

- A Transport copies its profile on first use. Later edits need a new Transport or `Transport.Clone`.
- HTTP/1.1 and HTTP/2 are supported. HTTP/3 is not.
- `DialTLSContext` replaces the TLS handshake, so the profile's ClientHello does not apply there.
- TCP and IP fingerprints come from your machine or proxy, not from fphttp.

## Supported browsers

| Browser     | Windows                 | macOS                   | Linux                   | Android      | iOS  |
| ----------- | ----------------------- | ----------------------- | ----------------------- | ------------ | ---- |
| Chrome      | 108 to 156              | 109 to 156              | 109 to 155              | 110 to 156   |      |
| Edge        | 119 to 155              | 119 to 155              | 119 to 155              | 140 to 155   |      |
| Brave       | 1.46 to 1.97            | 1.46 to 1.97            | 1.46 to 1.97            | 1.56 to 1.97 |      |
| Firefox     | 108 to 158              | 108 to 158              | 108 to 158              | 126 to 158   |      |
| Firefox ESR | 102, 115, 128, 140, 153 | 102, 115, 128, 140, 153 | 102, 115, 128, 140, 153 |              |      |
| Safari      |                         | 26.0, 27.0              |                         |              | 27.0 |

That is 3,589 stable builds across 707 release and platform pairs. A major version selects its newest build.
Chrome and Edge also keep an exact build you ask for; other browsers use their release line, which is all their
`User-Agent` shows.

## Upgrading from v1

| v1                                          | v2                                                     |
| ------------------------------------------- | ------------------------------------------------------ |
| `github.com/aarock1234/fphttp`              | `github.com/aarock1234/fphttp/v2`                      |
| `Transport.Fingerprint`                     | `Transport.Profile`                                    |
| `Chrome()`, `Firefox120()`, and the rest    | `NewProfile(browser, platform, version)`               |
| `browser.New(browser.Config{...})`          | `NewClient(profile)`                                   |
| `Client.DoWithOptions` and `RequestContext` | `Client.Do` with `Request.Destination` and `Initiator` |
| `Config.DefaultHeaders`                     | `Profile.Header`                                       |
| `Fingerprint.H2`                            | `Profile.HTTP2`                                        |

## Development

The `net/http` sources track Go main and are merged with `internal/cmd/syncstdlib`. Browser data lives in
`internal/catalog`, and a daily workflow regenerates it from official release feeds:

```sh
go generate ./internal/catalog
go run ./internal/cmd/verifyprofiles
go run ./internal/cmd/checksource
```

## License

BSD 3 Clause, the same as Go. See [LICENSE](LICENSE).
