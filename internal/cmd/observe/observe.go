package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	http "github.com/aarock1234/fphttp/v2"
	"github.com/aarock1234/fphttp/v2/cookiejar"
	"github.com/aarock1234/fphttp/v2/httptrace"
)

// maxResponseBytes bounds one diagnostic response body.
const maxResponseBytes = 10 << 20

// collectObservations selects the profile and sends the requested number of
// requests over each protocol. It returns the report built so far together
// with the first failure.
func collectObservations(ctx context.Context, opts options) (observationReport, error) {
	report := newReport(opts)

	profile, err := selectProfile(opts, &report.Profile)
	if err != nil {
		return report, err
	}

	// One jar for both protocols, so the second sees the cookies the first
	// stored, as one browser would.
	jar, err := cookiejar.New(nil)
	if err != nil {
		return report, fmt.Errorf("observe: create cookie jar: %w", err)
	}

	for _, protocol := range opts.protocols {
		observations, err := observeProtocol(ctx, opts, profile, jar, protocol)
		report.Observations = append(report.Observations, observations...)

		if err != nil {
			return report, err
		}
	}

	return report, nil
}

// selectProfile returns the profile opts select, with the requested
// Accept-Language applied, and records it in report. A version newer than
// the newest supported release is a warning: the newest release is used.
func selectProfile(opts options, report *profileReport) (*http.Profile, error) {
	profile, err := http.NewProfile(opts.browser, opts.platform, opts.version)
	if err != nil && !errors.Is(err, http.ErrVersionTooNew) {
		return nil, fmt.Errorf("observe: select profile: %w", err)
	}

	if err != nil {
		report.VersionTooNew = true
		report.Warning = err.Error()

		slog.Warn("observing the newest supported release instead", slog.Any("error", err))
	}

	// The Transport copies the profile on its first request, so the header
	// must change before any client uses it.
	if opts.acceptLanguage != "" {
		profile.Header.Set("Accept-Language", opts.acceptLanguage)
	}

	report.recordProfile(profile)

	return profile, nil
}

// observeProtocol sends opts.count sequential requests over one protocol
// with a client of its own.
func observeProtocol(
	ctx context.Context,
	opts options,
	profile *http.Profile,
	jar http.CookieJar,
	protocol observationProtocol,
) ([]observation, error) {
	client, err := observationClient(opts, profile, jar, protocol)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()

	var observations []observation

	for index := range opts.count {
		if opts.newConnections && index > 0 {
			client.CloseIdleConnections()
		}

		observed, err := observeRequest(ctx, opts, client, protocol, index+1)
		observations = append(observations, observed)

		if err != nil {
			return observations, err
		}
	}

	return observations, nil
}

// observeRequest sends one diagnostic request and records the response and
// what the trace saw.
func observeRequest(
	ctx context.Context,
	opts options,
	client *http.Client,
	protocol observationProtocol,
	sequence int,
) (observation, error) {
	observed := observation{
		Protocol:  protocol,
		Sequence:  sequence,
		Endpoint:  diagnosticEndpoint(protocol),
		StartedAt: time.Now().UTC(),
	}

	trace := new(requestTrace)
	ctx = httptrace.WithClientTrace(ctx, trace.clientTrace())

	request, err := newObservationRequest(ctx, opts, observed.Endpoint)
	if err != nil {
		return failedObservation(observed, trace, err)
	}

	response, err := client.Do(request)
	if err != nil {
		return failedObservation(observed, trace, fmt.Errorf("observe: fetch %s diagnostics: %w", protocol, err))
	}

	observed.StatusCode = response.StatusCode
	observed.HTTPProtocol = response.Proto
	observed.Uncompressed = response.Uncompressed
	observed.ResponseHeaders = response.Header.Clone()

	if response.TLS != nil {
		observed.TLS = tlsObservationFrom(*response.TLS)
	}

	payload, err := readPayload(response)
	if err != nil {
		return failedObservation(observed, trace, fmt.Errorf("observe: read %s diagnostics: %w", protocol, err))
	}

	if json.Valid(payload) {
		observed.Payload = json.RawMessage(payload)
	} else {
		observed.BodyBase64 = base64.StdEncoding.EncodeToString(payload)
	}

	observed.FinishedAt = time.Now().UTC()
	observed.Trace = trace.snapshot()

	return observed, nil
}

// newObservationRequest builds the diagnostic request with the browser
// context opts describe.
func newObservationRequest(ctx context.Context, opts options, endpoint string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("observe: create request: %w", err)
	}

	request.Destination = opts.destination
	request.Initiator = opts.initiator

	return request, nil
}

// readPayload reads and closes the response body, failing when it exceeds
// maxResponseBytes.
func readPayload(response *http.Response) ([]byte, error) {
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	closeErr := response.Body.Close()

	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}

	if len(payload) > maxResponseBytes {
		return nil, fmt.Errorf("diagnostic response exceeds %d bytes", maxResponseBytes)
	}

	return payload, nil
}

// failedObservation completes an observation that ended with err.
func failedObservation(observed observation, trace *requestTrace, err error) (observation, error) {
	observed.FinishedAt = time.Now().UTC()
	observed.Trace = trace.snapshot()
	observed.Error = err.Error()

	return observed, err
}

// diagnosticEndpoint returns the tls.but.sh endpoint that serves only
// protocol.
func diagnosticEndpoint(protocol observationProtocol) string {
	if protocol == protocolHTTP1 {
		return "https://h1.tls.but.sh/api/network"
	}

	return "https://h2.tls.but.sh/api/network"
}
