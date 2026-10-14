package main

import (
	"crypto/tls"
	"errors"

	http "github.com/aarock1234/fphttp/v2"
)

// observationClient returns a client that sends profile's requests over
// protocol only. Every setting is applied before the client's first
// request, because its Transport copies the profile then.
func observationClient(
	opts options,
	profile *http.Profile,
	jar http.CookieJar,
	protocol observationProtocol,
) (*http.Client, error) {
	client := http.NewClient(profile)
	client.Jar = jar
	client.Timeout = opts.timeout

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("observe: NewClient returned a client without an fphttp Transport")
	}

	transport.Protocols = onlyProtocol(protocol)
	transport.TLSClientConfig = &tls.Config{
		SessionTicketsDisabled: opts.disableResumption,
	}

	return client, nil
}

// onlyProtocol returns the Transport protocols that permit protocol alone.
// The Transport then offers only that protocol in the ClientHello's ALPN
// and ALPS extensions.
func onlyProtocol(protocol observationProtocol) *http.Protocols {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(protocol == protocolHTTP1)
	protocols.SetHTTP2(protocol == protocolHTTP2)

	return protocols
}
