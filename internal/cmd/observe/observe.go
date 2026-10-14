package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	http "github.com/aarock1234/fphttp/v2"
	"github.com/aarock1234/fphttp/v2/browser"
	"github.com/aarock1234/fphttp/v2/cookiejar"
	"github.com/aarock1234/fphttp/v2/httptrace"
)

const maxResponseBytes = 10 << 20

func collectObservations(ctx context.Context, opts options) (observationReport, error) {
	report := observationReport{
		CollectedAt:        time.Now().UTC(),
		Selector:           opts.selector,
		Kind:               opts.kind,
		UserAgentOSVersion: opts.userAgentOSVersion,
		ExecutionOS:        runtime.GOOS,
		ExecutionArch:      runtime.GOARCH,
		ProtocolSelection:  "each transport permits only its diagnostic protocol; ClientHello ALPN and ALPS are filtered accordingly",
		NewConnections:     opts.newConnections,
		ResumptionEnabled:  !opts.disableResumption,
	}

	profile, err := browser.Resolve(opts.selector)
	if err != nil {
		return report, fmt.Errorf("observe: select profile: %w", err)
	}
	report.Profile = profile.Descriptor()

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

func observeProtocol(ctx context.Context, opts options, profile *browser.Profile, jar http.CookieJar, protocol observationProtocol) ([]observation, error) {
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

func observationClient(opts options, profile *browser.Profile, jar http.CookieJar, protocol observationProtocol) (*browser.Client, error) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("observe: DefaultTransport is not an fphttp Transport")
	}
	transport = transport.Clone()
	transport.Protocols = &http.Protocols{}
	transport.Protocols.SetHTTP1(protocol == protocolHTTP1)
	transport.Protocols.SetHTTP2(protocol == protocolHTTP2)
	transport.TLSClientConfig = &tls.Config{
		SessionTicketsDisabled: opts.disableResumption,
	}

	client, err := browser.New(browser.Config{
		Profile:   profile,
		Transport: transport,
		Timeout:   opts.timeout,
		Jar:       jar,
	})
	if err != nil {
		return nil, fmt.Errorf("observe: create %s client: %w", protocol, err)
	}

	return client, nil
}

func observeRequest(ctx context.Context, opts options, client *browser.Client, protocol observationProtocol, sequence int) (observation, error) {
	observed := observation{
		Protocol:  protocol,
		Sequence:  sequence,
		Endpoint:  diagnosticEndpoint(protocol),
		StartedAt: time.Now().UTC(),
	}
	trace := new(requestTrace)
	ctx = httptrace.WithClientTrace(ctx, trace.clientTrace())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, observed.Endpoint, nil)
	if err != nil {
		return failedObservation(observed, trace, fmt.Errorf("observe: create request: %w", err))
	}

	response, err := client.DoWithOptions(request, browser.RequestOptions{
		Context: observationContext(opts),
	})
	if err != nil {
		return failedObservation(observed, trace, fmt.Errorf("observe: fetch %s diagnostics: %w", protocol, err))
	}
	observed.StatusCode = response.StatusCode
	observed.HTTPProtocol = response.Proto
	observed.ResponseHeaders = response.Header.Clone()
	if response.TLS != nil {
		observed.TLS = tlsObservationFrom(*response.TLS)
	}

	payload, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	closeErr := response.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return failedObservation(observed, trace, fmt.Errorf("observe: read %s diagnostics: %w", protocol, err))
	}
	if len(payload) > maxResponseBytes {
		return failedObservation(observed, trace, fmt.Errorf("observe: diagnostic response exceeds %d bytes", maxResponseBytes))
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

func failedObservation(observed observation, trace *requestTrace, err error) (observation, error) {
	observed.FinishedAt = time.Now().UTC()
	observed.Trace = trace.snapshot()
	observed.Error = err.Error()

	return observed, err
}

func observationContext(opts options) *browser.RequestContext {
	if opts.kind == kindBasic {
		return nil
	}

	metadata := &browser.RequestContext{
		AcceptLanguage: opts.acceptLanguage,
	}
	if opts.userAgentOSVersion != "" {
		metadata.Device = &browser.DeviceMetadata{
			UserAgentOSVersion: opts.userAgentOSVersion,
		}
	}
	if opts.kind == kindNavigation {
		metadata.Kind = browser.Navigation
		metadata.UserActivation = opts.userActivation
	} else {
		metadata.Kind = browser.Fetch
		metadata.Initiator = opts.initiator
	}

	return metadata
}

func diagnosticEndpoint(protocol observationProtocol) string {
	if protocol == protocolHTTP1 {
		return "https://h1.tls.but.sh/api/network"
	}

	return "https://h2.tls.but.sh/api/network"
}
