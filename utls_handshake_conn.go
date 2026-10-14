package http

import (
	"bytes"
	"net"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
)

// TLS record and handshake values handshakeConn reads.
const (
	recordHeaderLen = 5

	recordTypeChangeCipherSpec = 20
	recordTypeAlert            = 21
	recordTypeHandshake        = 22

	handshakeHeaderLen       = 4
	handshakeTypeServerHello = 2

	extensionSupportedVersions = 43
	extensionKeyShare          = 51

	// maxServerHelloLen bounds the handshake bytes handshakeConn buffers
	// while it waits for a ServerHello. A real ServerHello is far smaller.
	maxServerHelloLen = 1 << 16
)

// helloRetryRequestRandom is the ServerHello random that marks a
// HelloRetryRequest (RFC 8446, Section 4.1.3).
var helloRetryRequestRandom = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
	0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// handshakeConn wraps the connection under a profile handshake and reads
// the server's plaintext TLS records as uTLS receives them. It never
// changes what the client sends, and it stops looking once the server's
// records are encrypted.
//
// It does two things browsers do and uTLS does not:
//
//   - It accepts any minor version in a plaintext record header. RFC 8446,
//     Section 5.1 says legacy_record_version MUST be ignored, and some
//     servers send 0x0301 on the ServerHello that follows a
//     HelloRetryRequest. BoringSSL and NSS check only the major version of
//     plaintext records, but uTLS requires 0x0303 and fails the handshake,
//     so handshakeConn rewrites the minor version to 3 before uTLS reads
//     it. Plaintext record headers are neither authenticated nor part of
//     the handshake transcript. Encrypted records are left alone, so their
//     version is still checked exactly.
//   - It reports the key share group of the ServerHello to onServerHello
//     before uTLS reads the end of the message (see secondaryKeyShares).
//
// A handshakeConn is read by one goroutine at a time.
type handshakeConn struct {
	net.Conn

	// onServerHello, when set, receives the key share group of the final
	// ServerHello, which is not a HelloRetryRequest.
	onServerHello func(group utls.CurveID)

	// header holds the current record header, of which headerLen bytes have
	// arrived, and bodyLeft counts the record body bytes still to come.
	header    [recordHeaderLen]byte
	headerLen int
	bodyLeft  int

	// handshake buffers plaintext handshake bytes while collect is set,
	// until the final ServerHello is parsed.
	handshake []byte
	collect   bool

	// helloDone reports that the final ServerHello arrived, and tls13 that
	// it negotiated TLS 1.3, after which every server record is encrypted.
	// Before TLS 1.3, the server's ChangeCipherSpec record ends the
	// plaintext records.
	helloDone bool
	tls13     bool
	encrypted bool
}

// newHandshakeConn returns a handshakeConn reading from conn.
func newHandshakeConn(conn net.Conn) *handshakeConn {
	return &handshakeConn{
		Conn:    conn,
		collect: true,
	}
}

// Read reads from the underlying connection, inspecting the bytes while the
// server's records are still plaintext.
func (c *handshakeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !c.encrypted {
		c.inspect(p[:n])
	}

	return n, err
}

// inspect walks the record headers and bodies in data, which is the next
// part of the server's byte stream.
func (c *handshakeConn) inspect(data []byte) {
	for len(data) > 0 && !c.encrypted {
		if c.headerLen < recordHeaderLen {
			c.readHeaderByte(&data[0])
			data = data[1:]

			continue
		}

		body := data[:min(c.bodyLeft, len(data))]
		if c.header[0] == recordTypeHandshake && c.collect {
			c.readHandshake(body)
		}

		data = data[len(body):]
		c.bodyLeft -= len(body)
		if c.bodyLeft == 0 {
			c.endRecord()
		}
	}
}

// readHeaderByte records the next record header byte, rewriting the minor
// version of a plaintext record to 3.
func (c *handshakeConn) readHeaderByte(b *byte) {
	if c.headerLen == 2 && c.header[1] == 3 && isPlaintextRecordType(c.header[0]) {
		*b = 3
	}

	c.header[c.headerLen] = *b
	c.headerLen++

	if c.headerLen == recordHeaderLen {
		c.bodyLeft = int(c.header[3])<<8 | int(c.header[4])
		if c.bodyLeft == 0 {
			c.endRecord()
		}
	}
}

// endRecord finishes the current record and decides whether the records
// that follow are still plaintext.
func (c *handshakeConn) endRecord() {
	switch {
	case c.helloDone && c.tls13:
		c.encrypted = true

	case c.helloDone && c.header[0] == recordTypeChangeCipherSpec:
		c.encrypted = true
	}

	c.headerLen = 0
}

// readHandshake buffers plaintext handshake bytes and parses each complete
// message until the final ServerHello.
func (c *handshakeConn) readHandshake(body []byte) {
	c.handshake = append(c.handshake, body...)

	for c.collect && len(c.handshake) >= handshakeHeaderLen {
		length := int(c.handshake[1])<<16 | int(c.handshake[2])<<8 | int(c.handshake[3])
		if length > maxServerHelloLen {
			c.stopCollecting()

			return
		}

		if len(c.handshake) < handshakeHeaderLen+length {
			return
		}

		message := c.handshake[:handshakeHeaderLen+length]
		c.handshake = c.handshake[len(message):]
		c.readMessage(message)
	}
}

// readMessage handles one plaintext handshake message from the server.
func (c *handshakeConn) readMessage(message []byte) {
	if message[0] != handshakeTypeServerHello {
		c.stopCollecting()

		return
	}

	hello, ok := parseServerHello(message[handshakeHeaderLen:])
	if !ok {
		c.stopCollecting()

		return
	}

	if hello.retry {
		return
	}

	c.helloDone = true
	c.tls13 = hello.version == utls.VersionTLS13
	c.stopCollecting()

	if c.onServerHello != nil && hello.group != 0 {
		c.onServerHello(hello.group)
	}
}

// stopCollecting stops buffering handshake messages.
func (c *handshakeConn) stopCollecting() {
	c.collect = false
	c.handshake = nil
}

// isPlaintextRecordType reports whether a record of this type can arrive
// before the server's records are encrypted.
func isPlaintextRecordType(recordType byte) bool {
	switch recordType {
	case recordTypeChangeCipherSpec, recordTypeAlert, recordTypeHandshake:
		return true

	default:
		return false
	}
}

// serverHello is the part of a ServerHello handshakeConn reads.
type serverHello struct {
	// retry reports that the message is a HelloRetryRequest.
	retry bool

	// version is the negotiated version: supported_versions when present,
	// otherwise legacy_version.
	version uint16

	// group is the key share group, or zero without a key share.
	group utls.CurveID
}

// parseServerHello parses the body of a ServerHello message.
func parseServerHello(body []byte) (serverHello, bool) {
	input := cryptobyte.String(body)

	var (
		hello       serverHello
		random      []byte
		sessionID   cryptobyte.String
		cipherSuite uint16
		compression uint8
	)

	if !input.ReadUint16(&hello.version) ||
		!input.ReadBytes(&random, 32) ||
		!input.ReadUint8LengthPrefixed(&sessionID) ||
		!input.ReadUint16(&cipherSuite) ||
		!input.ReadUint8(&compression) {
		return serverHello{}, false
	}

	hello.retry = bytes.Equal(random, helloRetryRequestRandom)
	if input.Empty() {
		return hello, true
	}

	var extensions cryptobyte.String
	if !input.ReadUint16LengthPrefixed(&extensions) {
		return serverHello{}, false
	}

	for !extensions.Empty() {
		var (
			extension uint16
			data      cryptobyte.String
		)

		if !extensions.ReadUint16(&extension) || !extensions.ReadUint16LengthPrefixed(&data) {
			return serverHello{}, false
		}

		if !hello.readExtension(extension, data) {
			return serverHello{}, false
		}
	}

	return hello, true
}

// readExtension reads the supported_versions and key_share extensions and
// skips the others.
func (h *serverHello) readExtension(extension uint16, data cryptobyte.String) bool {
	switch extension {
	case extensionSupportedVersions:
		return data.ReadUint16(&h.version)

	case extensionKeyShare:
		var group uint16
		if !data.ReadUint16(&group) {
			return false
		}

		h.group = utls.CurveID(group)

		return true

	default:
		return true
	}
}
