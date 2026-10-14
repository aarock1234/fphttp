package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	http "github.com/aarock1234/fphttp/v2"
	"github.com/aarock1234/fphttp/v2/browser"
)

type observationReport struct {
	CollectedAt        time.Time          `json:"collected_at"`
	Selector           browser.Selector   `json:"selector"`
	Profile            browser.Descriptor `json:"profile"`
	Kind               requestKind        `json:"request_kind"`
	UserAgentOSVersion string             `json:"user_agent_os_version,omitempty"`
	ExecutionOS        string             `json:"execution_os"`
	ExecutionArch      string             `json:"execution_arch"`
	ProtocolSelection  string             `json:"protocol_selection"`
	NewConnections     bool               `json:"new_connections_between_requests"`
	ResumptionEnabled  bool               `json:"tls_resumption_enabled"`
	Observations       []observation      `json:"observations"`
	Error              string             `json:"error,omitempty"`
}

type observation struct {
	Protocol        observationProtocol `json:"requested_protocol"`
	Sequence        int                 `json:"sequence"`
	Endpoint        string              `json:"endpoint"`
	StartedAt       time.Time           `json:"started_at"`
	FinishedAt      time.Time           `json:"finished_at"`
	StatusCode      int                 `json:"status_code"`
	HTTPProtocol    string              `json:"http_protocol"`
	ResponseHeaders http.Header         `json:"response_headers,omitempty"`
	TLS             tlsObservation      `json:"negotiated_tls"`
	Trace           traceSnapshot       `json:"trace"`
	Payload         json.RawMessage     `json:"payload,omitempty"`
	BodyBase64      string              `json:"body_base64,omitempty"`
	Error           string              `json:"error,omitempty"`
}

type tlsObservation struct {
	Version     uint16 `json:"version"`
	CipherSuite uint16 `json:"cipher_suite"`
	CurveID     uint16 `json:"curve_id"`
	ALPN        string `json:"alpn"`
	DidResume   bool   `json:"did_resume"`
	ECHAccepted bool   `json:"ech_accepted"`
	Retry       bool   `json:"hello_retry_request"`
}

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

// writeOutput is the serialization boundary shared by observations and catalog
// snapshots. All request and profile data use concrete types before this point.
func writeOutput(path string, value any) (err error) {
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
