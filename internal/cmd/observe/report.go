package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	http "github.com/aarock1234/fphttp/v2"
)

// protocolSelection explains how each diagnostic transport limits itself to
// one protocol.
const protocolSelection = "each transport permits only its diagnostic protocol; ClientHello ALPN and ALPS are filtered accordingly"

// observationReport is the complete result of one observe run.
type observationReport struct {
	CollectedAt       time.Time     `json:"collected_at"`
	Profile           profileReport `json:"profile"`
	Request           requestReport `json:"request"`
	ExecutionOS       string        `json:"execution_os"`
	ExecutionArch     string        `json:"execution_arch"`
	ProtocolSelection string        `json:"protocol_selection"`
	NewConnections    bool          `json:"new_connections_between_requests"`
	ResumptionEnabled bool          `json:"tls_resumption_enabled"`
	Observations      []observation `json:"observations"`
	Error             string        `json:"error,omitempty"`
}

// profileReport records the requested release and the profile NewProfile
// resolved it to.
type profileReport struct {
	RequestedBrowser  http.Browser  `json:"requested_browser"`
	RequestedPlatform http.Platform `json:"requested_platform"`

	// RequestedVersion is empty when the newest release was requested.
	RequestedVersion http.Version `json:"requested_version"`

	// Description is Profile.String, such as "Chrome 152.0.7977.85 on
	// Windows". The resolved fields below are empty when NewProfile failed.
	Description string        `json:"description,omitempty"`
	Browser     http.Browser  `json:"browser,omitempty"`
	Platform    http.Platform `json:"platform,omitempty"`
	Version     http.Version  `json:"version,omitempty"`

	// VersionTooNew reports that the requested version is newer than the
	// newest supported release, which was observed instead. Warning holds
	// the error NewProfile returned with it.
	VersionTooNew bool   `json:"version_too_new"`
	Warning       string `json:"warning,omitempty"`
}

// requestReport records the browser context every request was sent with.
type requestReport struct {
	// Destination is the request's Destination; empty is a top-level page
	// load.
	Destination    http.Destination `json:"destination"`
	Initiator      string           `json:"initiator,omitempty"`
	AcceptLanguage string           `json:"accept_language,omitempty"`
}

// observation is one diagnostic request and what the endpoint reported.
type observation struct {
	Protocol        observationProtocol `json:"requested_protocol"`
	Sequence        int                 `json:"sequence"`
	Endpoint        string              `json:"endpoint"`
	StartedAt       time.Time           `json:"started_at"`
	FinishedAt      time.Time           `json:"finished_at"`
	StatusCode      int                 `json:"status_code"`
	HTTPProtocol    string              `json:"http_protocol"`
	Uncompressed    bool                `json:"uncompressed"`
	ResponseHeaders http.Header         `json:"response_headers,omitempty"`
	TLS             tlsObservation      `json:"negotiated_tls"`
	Trace           traceSnapshot       `json:"trace"`
	Payload         json.RawMessage     `json:"payload,omitempty"`
	BodyBase64      string              `json:"body_base64,omitempty"`
	Error           string              `json:"error,omitempty"`
}

// tlsObservation is the negotiated state of one TLS connection.
type tlsObservation struct {
	Version     uint16 `json:"version"`
	CipherSuite uint16 `json:"cipher_suite"`
	CurveID     uint16 `json:"curve_id"`
	ALPN        string `json:"alpn"`
	DidResume   bool   `json:"did_resume"`
	ECHAccepted bool   `json:"ech_accepted"`
	Retry       bool   `json:"hello_retry_request"`
}

// newReport starts the report of a run with everything known before the
// profile is selected.
func newReport(opts options) observationReport {
	report := observationReport{
		CollectedAt: time.Now().UTC(),
		Profile: profileReport{
			RequestedBrowser:  opts.browser,
			RequestedPlatform: opts.platform,
			RequestedVersion:  opts.version,
		},
		Request: requestReport{
			Destination:    opts.destination,
			AcceptLanguage: opts.acceptLanguage,
		},
		ExecutionOS:       runtime.GOOS,
		ExecutionArch:     runtime.GOARCH,
		ProtocolSelection: protocolSelection,
		NewConnections:    opts.newConnections,
		ResumptionEnabled: !opts.disableResumption,
	}

	if opts.initiator != nil {
		report.Request.Initiator = opts.initiator.String()
	}

	return report
}

// recordProfile stores the release profile resolves to.
func (r *profileReport) recordProfile(profile *http.Profile) {
	r.Description = profile.String()
	r.Browser = profile.Browser()
	r.Platform = profile.Platform()
	r.Version = profile.Version()
}

// tlsObservationFrom copies the negotiated values of a TLS connection.
func tlsObservationFrom(state tls.ConnectionState) tlsObservation {
	return tlsObservation{
		Version:     state.Version,
		CipherSuite: state.CipherSuite,
		CurveID:     uint16(state.CurveID),
		ALPN:        state.NegotiatedProtocol,
		DidResume:   state.DidResume,
		ECHAccepted: state.ECHAccepted,
		Retry:       state.HelloRetryRequest,
	}
}

// writeOutput writes value as indented JSON to path, or to stdout when path
// is "-". It never replaces an existing file.
func writeOutput[T any](path string, value T) (err error) {
	output := os.Stdout

	if path != "-" {
		output, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("observe: create report: %w", err)
		}

		defer func() {
			if closeErr := output.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("observe: close report: %w", closeErr))
			}
		}()
	}

	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("observe: write report: %w", err)
	}

	return nil
}
