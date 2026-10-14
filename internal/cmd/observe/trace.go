package main

import (
	"crypto/tls"
	"slices"
	"sync"
	"time"

	"github.com/aarock1234/fphttp/v2/httptrace"
)

// requestTrace collects the connection, handshake, and header events of one
// request. Its hooks may run on transport goroutines, so mu guards every
// field.
type requestTrace struct {
	mu          sync.Mutex
	connections []connectionObservation
	handshakes  []tlsObservation
	headers     []headerObservation
}

// traceSnapshot is a copy of the events a requestTrace collected.
type traceSnapshot struct {
	Connections []connectionObservation `json:"connections"`
	Handshakes  []tlsObservation        `json:"handshakes"`
	Headers     []headerObservation     `json:"written_headers"`
}

// connectionObservation is one connection the request obtained.
type connectionObservation struct {
	RecordedAt time.Time `json:"recorded_at"`
	LocalAddr  string    `json:"local_addr"`
	RemoteAddr string    `json:"remote_addr"`
	Reused     bool      `json:"reused"`
	WasIdle    bool      `json:"was_idle"`
}

// headerObservation is one header field the transport wrote, in wire order.
type headerObservation struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// clientTrace returns the hooks that feed t.
func (t *requestTrace) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn:          t.gotConnection,
		TLSHandshakeDone: t.handshakeDone,
		WroteHeaderField: t.wroteHeader,
	}
}

// gotConnection records the connection a request obtained.
func (t *requestTrace) gotConnection(info httptrace.GotConnInfo) {
	connection := connectionObservation{
		RecordedAt: time.Now().UTC(),
		Reused:     info.Reused,
		WasIdle:    info.WasIdle,
	}

	if info.Conn != nil {
		if local := info.Conn.LocalAddr(); local != nil {
			connection.LocalAddr = local.String()
		}

		if remote := info.Conn.RemoteAddr(); remote != nil {
			connection.RemoteAddr = remote.String()
		}
	}

	t.mu.Lock()
	t.connections = append(t.connections, connection)
	t.mu.Unlock()
}

// handshakeDone records a successful TLS handshake.
func (t *requestTrace) handshakeDone(state tls.ConnectionState, err error) {
	if err != nil {
		return
	}

	t.mu.Lock()
	t.handshakes = append(t.handshakes, tlsObservationFrom(state))
	t.mu.Unlock()
}

// wroteHeader records one header field the transport wrote.
func (t *requestTrace) wroteHeader(name string, values []string) {
	header := headerObservation{
		Name:   name,
		Values: slices.Clone(values),
	}

	t.mu.Lock()
	t.headers = append(t.headers, header)
	t.mu.Unlock()
}

// snapshot returns a copy of every event collected so far.
func (t *requestTrace) snapshot() traceSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()

	headers := make([]headerObservation, len(t.headers))
	for index, header := range t.headers {
		headers[index] = headerObservation{
			Name:   header.Name,
			Values: slices.Clone(header.Values),
		}
	}

	return traceSnapshot{
		Connections: slices.Clone(t.connections),
		Handshakes:  slices.Clone(t.handshakes),
		Headers:     headers,
	}
}
