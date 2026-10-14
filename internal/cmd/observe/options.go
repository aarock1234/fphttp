package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"strings"
	"time"

	http "github.com/aarock1234/fphttp/v2"
	"github.com/aarock1234/fphttp/v2/browser"
)

type observationProtocol string

const (
	protocolHTTP1 observationProtocol = "h1"
	protocolHTTP2 observationProtocol = "h2"
)

type requestKind string

const (
	kindBasic      requestKind = "basic"
	kindNavigation requestKind = "navigation"
	kindFetch      requestKind = "fetch"
)

type options struct {
	catalog            bool
	selector           browser.Selector
	protocols          []observationProtocol
	kind               requestKind
	initiator          *url.URL
	acceptLanguage     string
	userAgentOSVersion string
	userActivation     bool
	timeout            time.Duration
	count              int
	newConnections     bool
	disableResumption  bool
	outputPath         string
}

func parseOptions(arguments []string) (options, error) {
	var opts options
	var browserName, platformName, protocolName, kindName, initiator string

	flags := flag.NewFlagSet("observe", flag.ContinueOnError)
	flags.BoolVar(&opts.catalog, "catalog", false, "write the complete release catalog without sending requests")
	flags.StringVar(&browserName, "browser", "chrome", "browser: chrome, edge, brave, safari, or firefox")
	flags.StringVar(&platformName, "platform", "windows", "profile platform: windows, mac, linux, android, ios, or ipados")
	flags.StringVar(&opts.selector.Version, "version", "", "exact version or numeric prefix; empty selects the latest catalog entry")
	flags.StringVar(&opts.selector.Variant, "variant", "", "catalog variant; empty selects source-default")
	flags.StringVar(&opts.selector.Channel, "channel", "", "optional release channel constraint")
	flags.StringVar(&opts.selector.OSBuild, "os-build", "", "optional catalog operating system build constraint")
	flags.StringVar(&opts.selector.Device, "device", "", "optional catalog device constraint")
	flags.StringVar(&protocolName, "protocol", "both", "diagnostic endpoints: h1, h2, or both; each transport permits only that protocol")
	flags.StringVar(&kindName, "kind", string(kindBasic), "request semantics: basic, navigation, or fetch")
	flags.StringVar(&initiator, "initiator", "", "explicit initiating page URL; required for fetch")
	flags.StringVar(&opts.acceptLanguage, "accept-language", "", "explicit contextual Accept-Language value")
	flags.StringVar(&opts.userAgentOSVersion, "ua-os-version", "", "explicit User-Agent OS version; requires navigation or fetch context")
	flags.BoolVar(&opts.userActivation, "user-activation", false, "navigation follows an explicit user activation")
	flags.DurationVar(&opts.timeout, "timeout", 30*time.Second, "deadline for the complete collection, including response bodies")
	flags.IntVar(&opts.count, "count", 1, "number of sequential requests per protocol")
	flags.BoolVar(&opts.newConnections, "new-connections", false, "close idle connections between requests while retaining session caches")
	flags.BoolVar(&opts.disableResumption, "disable-resumption", false, "disable TLS session tickets for fresh handshake observations")
	flags.StringVar(&opts.outputPath, "output", "-", "report destination; - writes JSON to stdout")

	if err := flags.Parse(arguments); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, errors.New("observe: positional arguments are not supported")
	}
	if opts.timeout <= 0 || opts.count <= 0 {
		return options{}, errors.New("observe: timeout and count must be positive")
	}
	if strings.TrimSpace(opts.outputPath) == "" {
		return options{}, errors.New("observe: output destination must not be empty")
	}

	var err error
	opts.selector.Browser, err = parseBrowser(browserName)
	if err != nil {
		return options{}, err
	}
	opts.selector.Platform, err = parsePlatform(platformName)
	if err != nil {
		return options{}, err
	}
	opts.protocols, err = parseProtocols(protocolName)
	if err != nil {
		return options{}, err
	}
	opts.kind, err = parseKind(kindName)
	if err != nil {
		return options{}, err
	}
	if initiator != "" {
		opts.initiator, err = parseInitiator(initiator)
		if err != nil {
			return options{}, err
		}
	}
	if opts.kind == kindFetch && opts.initiator == nil {
		return options{}, errors.New("observe: fetch requires an explicit initiator")
	}
	if opts.userAgentOSVersion != "" && opts.kind == kindBasic {
		return options{}, errors.New("observe: ua-os-version requires navigation or fetch context")
	}

	return opts, nil
}

func parseBrowser(value string) (http.Browser, error) {
	selected := http.Browser(value)
	switch selected {
	case http.BrowserChrome, http.BrowserEdge, http.BrowserBrave, http.BrowserSafari, http.BrowserFirefox:
		return selected, nil
	default:
		return "", fmt.Errorf("observe: unsupported browser %q", value)
	}
}

func parsePlatform(value string) (http.Platform, error) {
	selected := http.Platform(value)
	switch selected {
	case http.PlatformWindows, http.PlatformMac, http.PlatformLinux, http.PlatformAndroid, http.PlatformIOS, http.PlatformIPadOS:
		return selected, nil
	default:
		return "", fmt.Errorf("observe: unsupported platform %q", value)
	}
}

func parseProtocols(value string) ([]observationProtocol, error) {
	switch value {
	case string(protocolHTTP1):
		return []observationProtocol{protocolHTTP1}, nil
	case string(protocolHTTP2):
		return []observationProtocol{protocolHTTP2}, nil
	case "both":
		return []observationProtocol{protocolHTTP1, protocolHTTP2}, nil
	default:
		return nil, fmt.Errorf("observe: unsupported protocol %q", value)
	}
}

func parseKind(value string) (requestKind, error) {
	selected := requestKind(value)
	switch selected {
	case kindBasic, kindNavigation, kindFetch:
		return selected, nil
	default:
		return "", fmt.Errorf("observe: unsupported request kind %q", value)
	}
}

func parseInitiator(value string) (*url.URL, error) {
	initiator, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("observe: parse initiator: %w", err)
	}
	if initiator.Hostname() == "" || initiator.Scheme != "http" && initiator.Scheme != "https" {
		return nil, errors.New("observe: initiator must be an absolute HTTP or HTTPS URL")
	}

	return initiator, nil
}
