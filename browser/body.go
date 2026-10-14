package browser

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	http "github.com/aarock1234/fphttp/v2"
)

type operationBody struct {
	io.ReadCloser
	cancel context.CancelFunc
	once   sync.Once
}

func (b *operationBody) Read(data []byte) (int, error) {
	n, err := b.ReadCloser.Read(data)
	if err != nil {
		b.once.Do(b.cancel)
	}

	return n, err
}

func (b *operationBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.cancel)

	return err
}

type decodedBody struct {
	reader  io.Reader
	source  io.ReadCloser
	closers []func() error
	once    sync.Once
	err     error
}

func (b *decodedBody) Read(data []byte) (int, error) {
	return b.reader.Read(data)
}

func (b *decodedBody) Close() error {
	b.once.Do(func() {
		for _, close := range b.closers {
			b.err = errors.Join(b.err, close())
		}
		b.err = errors.Join(b.err, b.source.Close())
	})

	return b.err
}

func decodeResponse(response *http.Response) error {
	if response.Body == nil || response.Body == http.NoBody {
		return nil
	}
	encoding := response.Header.Get("Content-Encoding")
	if encoding == "" || strings.EqualFold(encoding, "identity") {
		return nil
	}
	encodings := strings.Split(encoding, ",")
	for _, value := range encodings {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "gzip", "x-gzip", "deflate", "br", "zstd", "identity":
		default:
			// An explicit caller encoding can require an application decoder.
			return nil
		}
	}
	body := &decodedBody{
		reader: response.Body,
		source: response.Body,
	}
	response.Body = body
	for index := len(encodings) - 1; index >= 0; index-- {
		reader, close, err := decoder(body.reader, strings.ToLower(strings.TrimSpace(encodings[index])))
		if err != nil {
			_ = body.Close()

			return fmt.Errorf("browser: decode response: %w", err)
		}
		body.reader = reader
		if close != nil {
			body.closers = append(body.closers, close)
		}
	}
	response.Header.Del("Content-Encoding")
	response.Header.Del("Content-Length")
	response.ContentLength = -1
	response.Uncompressed = true

	return nil
}

func decoder(reader io.Reader, encoding string) (io.Reader, func() error, error) {
	switch encoding {
	case "gzip", "x-gzip":
		decoded, err := gzip.NewReader(reader)
		if err != nil {
			return nil, nil, err
		}

		return decoded, decoded.Close, nil
	case "deflate":
		buffered := bufio.NewReader(reader)
		header, err := buffered.Peek(2)
		if err != nil {
			return nil, nil, err
		}
		if header[0]&15 == 8 && header[0]>>4 <= 7 && (int(header[0])*256+int(header[1]))%31 == 0 {
			decoded, err := zlib.NewReader(buffered)
			if err != nil {
				return nil, nil, err
			}

			return decoded, decoded.Close, nil
		}
		decoded := flate.NewReader(buffered)

		return decoded, decoded.Close, nil
	case "br":
		return brotli.NewReader(reader), nil, nil
	case "zstd":
		decoded, err := zstd.NewReader(reader, zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, nil, err
		}
		close := func() error {
			decoded.Close()

			return nil
		}

		return decoded, close, nil
	default:
		return reader, nil, nil
	}
}
