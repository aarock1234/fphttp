package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	http "github.com/aarock1234/fphttp/v2"
)

// observationProtocol is the one protocol a diagnostic transport permits.
type observationProtocol string

// Diagnostic protocols, named as the -protocol flag accepts them.
const (
	protocolHTTP1 observationProtocol = "h1"
	protocolHTTP2 observationProtocol = "h2"
)

// requestKind is a -kind shorthand for a common Destination.
type requestKind string

const (
	// kindNavigation is a top-level page load: the zero Destination.
	kindNavigation requestKind = "navigation"

	// kindFetch is a fetch() call: DestinationEmpty.
	kindFetch requestKind = "fetch"
)

// knownDestinations lists every Destination a Transport with a Profile
// accepts.
var knownDestinations = []http.Destination{
	http.DestinationDocument,
	http.DestinationIframe,
	http.DestinationFrame,
	http.DestinationEmpty,
	http.DestinationImage,
	http.DestinationScript,
	http.DestinationStyle,
	http.DestinationFont,
	http.DestinationAudio,
	http.DestinationVideo,
	http.DestinationTrack,
	http.DestinationManifest,
	http.DestinationObject,
	http.DestinationEmbed,
	http.DestinationWorker,
	http.DestinationSharedWorker,
	http.DestinationServiceWorker,
	http.DestinationReport,
	http.DestinationXSLT,
	http.DestinationWebSocket,
}

// options holds the validated command-line flags.
type options struct {
	catalog           bool
	browser           http.Browser
	platform          http.Platform
	version           http.Version
	protocols         []observationProtocol
	destination       http.Destination
	initiator         *url.URL
	acceptLanguage    string
	timeout           time.Duration
	count             int
	newConnections    bool
	disableResumption bool
	outputPath        string
}

// flagValues holds the command-line values that need parsing before they
// become options.
type flagValues struct {
	browser     string
	platform    string
	version     string
	protocol    string
	kind        string
	destination string
	initiator   string
}

// parseOptions reads and validates the command-line flags.
func parseOptions(arguments []string) (options, error) {
	var (
		opts   options
		values flagValues
	)

	flags := newFlagSet(&opts, &values)
	if err := flags.Parse(arguments); err != nil {
		return options{}, err
	}

	if flags.NArg() != 0 {
		return options{}, errors.New("observe: positional arguments are not supported")
	}

	if err := opts.applyValues(values); err != nil {
		return options{}, err
	}

	if err := opts.validate(); err != nil {
		return options{}, err
	}

	return opts, nil
}

// newFlagSet defines every flag, storing plain values in opts and values
// that need parsing in values.
func newFlagSet(opts *options, values *flagValues) *flag.FlagSet {
	flags := flag.NewFlagSet("observe", flag.ContinueOnError)

	flags.BoolVar(&opts.catalog, "catalog", false, "write the supported release catalog without sending requests")

	flags.StringVar(&values.browser, "browser", string(http.BrowserChrome), "browser: chrome, edge, brave, firefox, firefox-esr, or safari")
	flags.StringVar(&values.platform, "platform", string(http.PlatformWindows), "platform: windows, mac, linux, android, ios, or ipados")
	flags.StringVar(&values.version, "version", string(http.Latest), "browser version as NewProfile accepts it, such as 152, 152.0.7977.85, or 1.90; empty selects the newest release")

	flags.StringVar(&values.protocol, "protocol", "both", "diagnostic endpoints: h1, h2, or both; each transport permits only that protocol")
	flags.StringVar(&values.kind, "kind", "", "request shorthand: navigation (a top-level page load, the default) or fetch (a fetch() call, requires -initiator); Sec-Fetch-User follows the destination rules, so only top-level page loads send ?1")
	flags.StringVar(&values.destination, "destination", "", "request destination as sent in Sec-Fetch-Dest, such as image, script, style, or iframe; cannot be combined with -kind and requires -initiator unless it is document")
	flags.StringVar(&values.initiator, "initiator", "", "URL of the page that started the request; required for every destination but a top-level page load")
	flags.StringVar(&opts.acceptLanguage, "accept-language", "", "Accept-Language value that replaces the profile's default")

	flags.DurationVar(&opts.timeout, "timeout", 30*time.Second, "deadline for the complete collection, including response bodies")
	flags.IntVar(&opts.count, "count", 1, "number of sequential requests per protocol")
	flags.BoolVar(&opts.newConnections, "new-connections", false, "close idle connections between requests while keeping the TLS session cache")
	flags.BoolVar(&opts.disableResumption, "disable-resumption", false, "disable TLS session tickets for fresh handshake observations")
	flags.StringVar(&opts.outputPath, "output", "-", "report destination; - writes JSON to stdout")

	return flags
}

// applyValues parses the raw flag values into opts.
func (o *options) applyValues(values flagValues) error {
	o.browser = http.Browser(values.browser)
	o.platform = http.Platform(values.platform)
	o.version = http.Version(values.version)

	protocols, err := parseProtocols(values.protocol)
	if err != nil {
		return err
	}

	destination, err := parseDestination(values.kind, values.destination)
	if err != nil {
		return err
	}

	o.protocols = protocols
	o.destination = destination

	if values.initiator == "" {
		return nil
	}

	initiator, err := parseInitiator(values.initiator)
	if err != nil {
		return err
	}

	o.initiator = initiator

	return nil
}

// validate checks the rules that span several flags.
func (o *options) validate() error {
	if o.timeout <= 0 || o.count <= 0 {
		return errors.New("observe: timeout and count must be positive")
	}

	if strings.TrimSpace(o.outputPath) == "" {
		return errors.New("observe: output destination must not be empty")
	}

	if o.initiator == nil && !topLevel(o.destination) {
		return fmt.Errorf("observe: destination %q requires -initiator", o.destination)
	}

	return nil
}

// parseProtocols returns the protocols named by the -protocol flag.
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

// parseDestination resolves the -kind shorthand or the -destination value.
// A top-level page load is the zero Destination.
func parseDestination(kind, destination string) (http.Destination, error) {
	if kind != "" && destination != "" {
		return "", errors.New("observe: use either -kind or -destination")
	}

	if destination != "" {
		selected := http.Destination(destination)
		if !slices.Contains(knownDestinations, selected) {
			return "", fmt.Errorf("observe: unknown destination %q", destination)
		}

		return selected, nil
	}

	switch requestKind(kind) {
	case "", kindNavigation:
		return "", nil
	case kindFetch:
		return http.DestinationEmpty, nil
	default:
		return "", fmt.Errorf("observe: unsupported request kind %q", kind)
	}
}

// parseInitiator parses the -initiator URL, which must be absolute HTTP or
// HTTPS.
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

// topLevel reports whether destination is a top-level page load, the only
// request a browser may send without an initiating page.
func topLevel(destination http.Destination) bool {
	return destination == "" || destination == http.DestinationDocument
}
