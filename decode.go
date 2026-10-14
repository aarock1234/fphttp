package http

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"io/fs"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// errConcurrentDecodedRead reports a Read on a decoded response body while
// another Read of it is in progress.
var errConcurrentDecodedRead = errors.New("fphttp: concurrent read on decoded response body")

// maxUndecodedTail is how many bytes a decoded body reads past the end of
// its encoded stream to reach the end of the response body, so the
// HTTP/1.1 connection can be reused. Anything longer is left unread.
const maxUndecodedTail = 2 << 10

// maxContentCodings is the most content codings a response may stack for
// fphttp to decode it. Each coding costs a decoder, so a hostile
// Content-Encoding listing thousands would otherwise cost gigabytes before
// any content arrives. Firefox applies at most 16 codings, and real servers
// apply one; a response listing more is left encoded, as for a coding
// fphttp does not decode.
const maxContentCodings = 16

// maxZstdWindow is the largest window a zstd frame may declare, 8 MiB. RFC
// 9659 limits the zstd content coding to it, and browsers enforce it, so a
// browser rejects any frame that needs more. Without the limit, a frame
// header of a few bytes could make the decoder allocate 512 MiB. A frame
// over the limit fails from Read.
const maxZstdWindow = 8 << 20

// decodeResponse makes resp's Body yield the content the server encoded,
// when every content coding that Content-Encoding lists is one fphttp
// decodes: gzip, x-gzip, deflate, br, zstd, or identity. It then deletes
// Content-Encoding and Content-Length, sets ContentLength to -1, and sets
// Uncompressed, as the Transport does for the gzip it asks for itself.
// Otherwise resp is unchanged, and the caller receives the body as the
// server encoded it.
//
// Nothing is read before the first Read of the new Body, so a response
// without a body, such as the response to a HEAD request or a 204 or 304
// response, and an empty body stay valid. Decoding errors surface from Read.
// A writable body, which a 101 Switching Protocols response carries, is
// never wrapped.
//
// A 206 Partial Content response is never decoded either: its body is a
// byte range of the encoded content, which no decoder can read on its own,
// so the caller receives it with Content-Encoding intact.
func decodeResponse(resp *Response) {
	if resp.Body == nil || resp.Body == NoBody || resp.bodyIsWritable() {
		return
	}

	if resp.StatusCode == StatusPartialContent {
		return
	}

	codings, ok := contentCodings(resp.Header.Values("Content-Encoding"))
	if !ok || len(codings) == 0 {
		return
	}

	resp.Body = &decodedBody{
		source:  resp.Body,
		codings: codings,
	}

	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	resp.Uncompressed = true
}

// contentCodings returns the content codings that Content-Encoding field
// values list, lowercased and in the order the server applied them. It
// leaves out identity, which changes nothing, and empty list members. It
// reports false when a coding is not one fphttp decodes, or when there are
// more than maxContentCodings.
func contentCodings(values []string) ([]string, bool) {
	var codings []string

	for _, value := range values {
		for coding := range strings.SplitSeq(value, ",") {
			coding = strings.ToLower(strings.TrimSpace(coding))

			switch coding {
			case "", "identity":
				continue

			case "gzip", "x-gzip", "deflate", "br", "zstd":
				if len(codings) == maxContentCodings {
					return nil, false
				}

				codings = append(codings, coding)

			default:
				return nil, false
			}
		}
	}

	return codings, true
}

// decodedBody is a response body that yields its source decoded through
// one decoder per content coding. It builds the decoders on the first
// Read, so creating it reads nothing, and a source that turns out to be
// empty reads as an empty body.
//
// Read and Close may be called concurrently, as on any response body: Close
// closes the source, which ends a Read in progress, and the decoders that
// Read holds are released when it returns. Close releases the decoders and
// closes the source exactly once.
type decodedBody struct {
	// source is the body as received from the server.
	source io.ReadCloser

	// codings lists the content codings in the order the server applied
	// them. The decoders undo them in reverse order.
	codings []string

	// mu guards chain and err.
	mu sync.Mutex

	// chain holds the decoders between Reads. It is nil before the first
	// Read, while a Read holds it, and after Close.
	chain *decoderChain

	// err is what every later Read returns: the error that building the
	// decoders failed with, errConcurrentDecodedRead while a Read holds the
	// decoders, or fs.ErrClosed after Close.
	err error

	// closeOnce runs Close's work once.
	closeOnce sync.Once

	// closeErr is the error from closing source, which every Close
	// returns.
	closeErr error
}

// Read reads decoded content. The first Read builds the decoders, which
// reads the start of the source.
func (b *decodedBody) Read(p []byte) (int, error) {
	chain, err := b.acquire()
	if err != nil {
		return 0, err
	}

	defer b.release(chain)

	return chain.Read(p)
}

// Close releases the decoders and closes the source. Later calls do nothing
// and return the same error.
func (b *decodedBody) Close() error {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		idle := b.chain
		b.chain = nil
		b.err = fs.ErrClosed
		b.mu.Unlock()

		idle.close()
		b.closeErr = b.source.Close()
	})

	return b.closeErr
}

// acquire takes the decoders for one Read, building them on the first
// Read. Until release returns them, other Reads fail with
// errConcurrentDecodedRead.
func (b *decodedBody) acquire() (*decoderChain, error) {
	chain, err := b.take()
	if err != nil || chain != nil {
		return chain, err
	}

	// Building reads the network, so it runs without the lock, and Close
	// can interrupt it by closing the source.
	chain, buildErr := newDecoderChain(b.source, b.codings)
	if err := b.adopt(chain, buildErr); err != nil {
		return nil, err
	}

	return chain, nil
}

// take marks a Read in progress and returns the decoders built by an
// earlier Read, or nil when this Read must build them. It fails when a
// Read is already in progress, building failed, or the body is closed.
func (b *decodedBody) take() (*decoderChain, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.err != nil {
		return nil, b.err
	}

	chain := b.chain
	b.chain = nil
	b.err = errConcurrentDecodedRead

	return chain, nil
}

// adopt records the outcome of building the decoders and returns the error
// the Read fails with, or nil. A building error becomes the error of every
// later Read. When Close ran meanwhile, the new decoders are released and
// the Read fails as closed.
func (b *decodedBody) adopt(chain *decoderChain, buildErr error) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.err != errConcurrentDecodedRead {
		chain.close()

		return b.err
	}

	if buildErr != nil {
		b.err = buildErr

		return buildErr
	}

	return nil
}

// release returns the decoders after a Read, or releases them when Close
// ran during the Read.
func (b *decodedBody) release(chain *decoderChain) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.err != errConcurrentDecodedRead {
		chain.close()

		return
	}

	b.chain = chain
	b.err = nil
}

// decoderChain decodes a body through one decoder per content coding.
type decoderChain struct {
	// reader yields the decoded content: the decoder of the first coding the
	// server applied, or source itself for an empty body.
	reader io.Reader

	// source is the buffered body as received, which the outermost decoder
	// reads.
	source *bufio.Reader

	// releases frees the resources of each decoder that holds any.
	releases []func()
}

// newDecoderChain builds the decoders that undo codings, the content
// codings in the order the server applied them, over source. Building reads
// the start of source, so it blocks until the body begins. An empty source
// needs no decoders and reads as an empty body.
func newDecoderChain(source io.Reader, codings []string) (*decoderChain, error) {
	buffered := bufio.NewReader(source)
	chain := &decoderChain{
		reader: buffered,
		source: buffered,
	}

	if _, err := buffered.Peek(1); err != nil {
		if err == io.EOF {
			return chain, nil
		}

		return nil, err
	}

	for index := len(codings) - 1; index >= 0; index-- {
		if err := chain.push(codings[index]); err != nil {
			chain.close()

			return nil, err
		}
	}

	return chain, nil
}

// push adds the decoder of one content coding on top of the chain.
func (c *decoderChain) push(coding string) error {
	switch coding {
	case "gzip", "x-gzip":
		decoder, err := gzip.NewReader(c.reader)
		if err != nil {
			return err
		}

		c.add(decoder, func() { _ = decoder.Close() })

	case "deflate":
		decoder, err := newDeflateReader(c.reader)
		if err != nil {
			return err
		}

		c.add(decoder, func() { _ = decoder.Close() })

	case "br":
		c.reader = brotli.NewReader(c.reader)

	case "zstd":
		decoder, err := newZstdReader(c.reader)
		if err != nil {
			return err
		}

		c.add(decoder, decoder.Close)
	}

	return nil
}

// add makes decoder the top of the chain, with release freeing its
// resources.
func (c *decoderChain) add(decoder io.Reader, release func()) {
	c.reader = decoder
	c.releases = append(c.releases, release)
}

// Read reads decoded content. When the decoders reach the end of the
// content, it also reads the source to its end, within maxUndecodedTail
// bytes, because an HTTP/1.1 connection is reused only once its response
// body has been read to the end.
func (c *decoderChain) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if err == io.EOF {
		_, _ = io.CopyN(io.Discard, c.source, maxUndecodedTail)
	}

	return n, err
}

// close releases every decoder. It is safe on a nil chain and on a chain
// already closed.
func (c *decoderChain) close() {
	if c == nil {
		return
	}

	for _, release := range c.releases {
		release()
	}

	c.releases = nil
}

// newZstdReader returns a decoder of the zstd content coding that decodes
// on the calling goroutine and refuses frames whose window exceeds
// maxZstdWindow.
func newZstdReader(r io.Reader) (*zstd.Decoder, error) {
	return zstd.NewReader(
		r,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxWindow(maxZstdWindow),
	)
}

// newDeflateReader returns a decoder of the deflate content coding. The
// coding is a zlib stream (RFC 1950), but some servers send a raw deflate
// stream (RFC 1951) instead, so the decoder tells them apart by the first
// two bytes, as browsers do. Reading those bytes blocks until they arrive.
func newDeflateReader(r io.Reader) (io.ReadCloser, error) {
	buffered := bufio.NewReader(r)

	// A short or failed Peek leaves too few bytes for a zlib header; the
	// raw decoder then reports the buffered reader's error on Read.
	header, _ := buffered.Peek(2)
	if !zlibHeader(header) {
		return flate.NewReader(buffered), nil
	}

	return zlib.NewReader(buffered)
}

// zlibHeader reports whether header, the first two bytes of a stream, is a
// valid zlib header (RFC 1950, section 2.2): the deflate method, a window
// of at most 32 KiB, and a check value that makes the pair a multiple of 31.
func zlibHeader(header []byte) bool {
	if len(header) != 2 {
		return false
	}

	method := header[0] & 0x0f
	window := header[0] >> 4
	check := (uint16(header[0])<<8 | uint16(header[1])) % 31

	return method == 8 && window <= 7 && check == 0
}
