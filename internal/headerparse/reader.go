// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package headerparse provides Go's bounded MIME header parser without
// relying on runtime linknames. The line and header parsing functions are
// copied from net/textproto in Go 1.27.1. Dot-encoding support is omitted
// because HTTP headers are not dot-encoded.
package headerparse

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math"
	"net/textproto"
	"sync"
)

type reader struct {
	R   *bufio.Reader
	buf []byte
}

func isASCIILetter(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

const toLower = 'a' - 'A'

var (
	colon              = []byte(":")
	nl                 = []byte("\n")
	errMessageTooLarge = errors.New("message too large")
	commonHeader       map[string]string
	commonHeaderOnce   sync.Once
)

// ReadMIMEHeader reads HTTP header fields with memory and field-count limits.
func ReadMIMEHeader(input *bufio.Reader, maxMemory, maxHeaders int64) (textproto.MIMEHeader, error) {
	return readMIMEHeader(&reader{R: input}, maxMemory, maxHeaders)
}

func (r *reader) readLineSlice(lim int64) ([]byte, error) {
	var line []byte
	for {
		l, more, err := r.R.ReadLine()
		if err != nil {
			return nil, err
		}
		if lim >= 0 && int64(len(line))+int64(len(l)) > lim {
			return nil, errMessageTooLarge
		}
		// Avoid the copy if the first call produced a full line.
		if line == nil && !more {
			return l, nil
		}
		line = append(line, l...)
		if !more {
			break
		}
	}
	return line, nil
}

func trim(s []byte) []byte {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	s = s[i:]
	n := len(s) - 1
	for n >= 0 && (s[n] == ' ' || s[n] == '\t') {
		n--
	}
	return s[:n+1]
}

func (r *reader) readContinuedLineSlice(lim int64, validateFirstLine func([]byte) error) ([]byte, error) {
	if validateFirstLine == nil {
		return nil, fmt.Errorf("missing validateFirstLine func")
	}

	// Read the first line.
	line, err := r.readLineSlice(lim)
	if err != nil {
		return nil, err
	}
	if len(line) == 0 { // blank line - no continuation
		return line, nil
	}

	if err := validateFirstLine(line); err != nil {
		return nil, err
	}

	// Optimistically assume that we have started to buffer the next line
	// and it starts with an ASCII letter (the next header key), or a blank
	// line, so we can avoid copying that buffered data around in memory
	// and skipping over non-existent whitespace.
	if r.R.Buffered() > 1 {
		peek, _ := r.R.Peek(2)
		if len(peek) > 0 && (isASCIILetter(peek[0]) || peek[0] == '\n') ||
			len(peek) == 2 && peek[0] == '\r' && peek[1] == '\n' {
			return trim(line), nil
		}
	}

	// ReadByte or the next readLineSlice will flush the read buffer;
	// copy the slice into buf.
	r.buf = append(r.buf[:0], trim(line)...)

	if lim < 0 {
		lim = math.MaxInt64
	}
	lim -= int64(len(r.buf))

	// Read continuation lines.
	for r.skipSpace() > 0 {
		r.buf = append(r.buf, ' ')
		if int64(len(r.buf)) >= lim {
			return nil, errMessageTooLarge
		}
		line, err := r.readLineSlice(lim - int64(len(r.buf)))
		if err != nil {
			break
		}
		r.buf = append(r.buf, trim(line)...)
	}
	return r.buf, nil
}

func (r *reader) skipSpace() int {
	n := 0
	for {
		c, err := r.R.ReadByte()
		if err != nil {
			// Bufio will keep err until next read.
			break
		}
		if c != ' ' && c != '\t' {
			r.R.UnreadByte()
			break
		}
		n++
	}
	return n
}

func readMIMEHeader(r *reader, maxMemory, maxHeaders int64) (textproto.MIMEHeader, error) {
	// Avoid lots of small slice allocations later by allocating one
	// large one ahead of time which we'll cut up into smaller
	// slices. If this isn't big enough later, we allocate small ones.
	var strs []string
	hint := r.upcomingHeaderKeys()
	if hint > 0 {
		if hint > 1000 {
			hint = 1000 // set a cap to avoid overallocation
		}
		strs = make([]string, hint)
	}

	m := make(textproto.MIMEHeader, hint)

	// Account for 400 bytes of overhead for the MIMEHeader, plus 200 bytes per entry.
	// Benchmarking map creation as of go1.20, a one-entry MIMEHeader is 416 bytes and large
	// MIMEHeaders average about 200 bytes per entry.
	maxMemory -= 400
	const mapEntryOverhead = 200

	// The first line cannot start with a leading space.
	if buf, err := r.R.Peek(1); err == nil && (buf[0] == ' ' || buf[0] == '\t') {
		const errorLimit = 80 // arbitrary limit on how much of the line we'll quote
		line, err := r.readLineSlice(errorLimit)
		if err != nil {
			return m, err
		}
		return m, textproto.ProtocolError(fmt.Sprintf("malformed MIME header initial line: %q", line))
	}

	for {
		kv, err := r.readContinuedLineSlice(maxMemory, mustHaveFieldNameColon)
		if len(kv) == 0 {
			return m, err
		}

		// Key ends at first colon.
		k, v, ok := bytes.Cut(kv, colon)
		if !ok {
			return m, textproto.ProtocolError(fmt.Sprintf("malformed MIME header line: %q", kv))
		}
		key, ok := canonicalMIMEHeaderKey(k)
		if !ok {
			return m, textproto.ProtocolError(fmt.Sprintf("malformed MIME header line: %q", kv))
		}
		for _, c := range v {
			if !validHeaderValueByte(c) {
				return m, textproto.ProtocolError(fmt.Sprintf("malformed MIME header line: %q", kv))
			}
		}

		maxHeaders--
		if maxHeaders < 0 {
			return nil, errMessageTooLarge
		}

		// Skip initial spaces in value.
		value := string(bytes.TrimLeft(v, " \t"))

		vv := m[key]
		if vv == nil {
			maxMemory -= int64(len(key))
			maxMemory -= mapEntryOverhead
		}
		maxMemory -= int64(len(value))
		if maxMemory < 0 {
			return m, errMessageTooLarge
		}
		if vv == nil && len(strs) > 0 {
			// More than likely this will be a single-element key.
			// Most headers aren't multi-valued.
			// Set the capacity on strs[0] to 1, so any future append
			// won't extend the slice into the other strings.
			vv, strs = strs[:1:1], strs[1:]
			vv[0] = value
			m[key] = vv
		} else {
			m[key] = append(vv, value)
		}

		if err != nil {
			return m, err
		}
	}
}

func mustHaveFieldNameColon(line []byte) error {
	if bytes.IndexByte(line, ':') < 0 {
		return textproto.ProtocolError(fmt.Sprintf("malformed MIME header: missing colon: %q", line))
	}
	return nil
}

func (r *reader) upcomingHeaderKeys() (n int) {
	// Try to determine the 'hint' size.
	r.R.Peek(1) // force a buffer load if empty
	s := r.R.Buffered()
	if s == 0 {
		return
	}
	peek, _ := r.R.Peek(s)
	for len(peek) > 0 && n < 1000 {
		var line []byte
		line, peek, _ = bytes.Cut(peek, nl)
		if len(line) == 0 || (len(line) == 1 && line[0] == '\r') {
			// Blank line separating headers from the body.
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Folded continuation of the previous line.
			continue
		}
		n++
	}
	return n
}

func validHeaderFieldByte(c byte) bool {
	// mask is a 128-bit bitmap with 1s for allowed bytes,
	// so that the byte c can be tested with a shift and an and.
	// If c >= 128, then 1<<c and 1<<(c-64) will both be zero,
	// and this function will return false.
	const mask = 0 |
		(1<<(10)-1)<<'0' |
		(1<<(26)-1)<<'a' |
		(1<<(26)-1)<<'A' |
		1<<'!' |
		1<<'#' |
		1<<'$' |
		1<<'%' |
		1<<'&' |
		1<<'\'' |
		1<<'*' |
		1<<'+' |
		1<<'-' |
		1<<'.' |
		1<<'^' |
		1<<'_' |
		1<<'`' |
		1<<'|' |
		1<<'~'
	return ((uint64(1)<<c)&(mask&(1<<64-1)) |
		(uint64(1)<<(c-64))&(mask>>64)) != 0
}

func validHeaderValueByte(c byte) bool {
	// mask is a 128-bit bitmap with 1s for allowed bytes,
	// so that the byte c can be tested with a shift and an and.
	// If c >= 128, then 1<<c and 1<<(c-64) will both be zero.
	// Since this is the obs-text range, we invert the mask to
	// create a bitmap with 1s for disallowed bytes.
	const mask = 0 |
		(1<<(0x7f-0x21)-1)<<0x21 | // VCHAR: %x21-7E
		1<<0x20 | // SP: %x20
		1<<0x09 // HTAB: %x09
	return ((uint64(1)<<c)&^(mask&(1<<64-1)) |
		(uint64(1)<<(c-64))&^(mask>>64)) == 0
}

func canonicalMIMEHeaderKey(a []byte) (_ string, ok bool) {
	if len(a) == 0 {
		return "", false
	}

	// See if a looks like a header key. If not, return it unchanged.
	noCanon := false
	for _, c := range a {
		if validHeaderFieldByte(c) {
			continue
		}
		// Don't canonicalize.
		if c == ' ' {
			// We accept invalid headers with a space before the
			// colon, but must not canonicalize them.
			// See https://go.dev/issue/34540.
			noCanon = true
			continue
		}
		return string(a), false
	}
	if noCanon {
		return string(a), true
	}

	upper := true
	for i, c := range a {
		// Canonicalize: first letter upper case
		// and upper case after each dash.
		// (Host, User-Agent, If-Modified-Since).
		// MIME headers are ASCII only, so no Unicode issues.
		if upper && 'a' <= c && c <= 'z' {
			c -= toLower
		} else if !upper && 'A' <= c && c <= 'Z' {
			c += toLower
		}
		a[i] = c
		upper = c == '-' // for next time
	}
	commonHeaderOnce.Do(initCommonHeader)
	// The compiler recognizes m[string(byteSlice)] as a special
	// case, so a copy of a's bytes into a new string does not
	// happen in this map lookup:
	if v := commonHeader[string(a)]; v != "" {
		return v, true
	}
	return string(a), true
}

func initCommonHeader() {
	commonHeader = make(map[string]string)
	for _, v := range []string{
		"Accept",
		"Accept-Charset",
		"Accept-Encoding",
		"Accept-Language",
		"Accept-Ranges",
		"Cache-Control",
		"Cc",
		"Connection",
		"Content-Id",
		"Content-Language",
		"Content-Length",
		"Content-Transfer-Encoding",
		"Content-Type",
		"Cookie",
		"Date",
		"Dkim-Signature",
		"Etag",
		"Expires",
		"From",
		"Host",
		"If-Modified-Since",
		"If-None-Match",
		"In-Reply-To",
		"Last-Modified",
		"Location",
		"Message-Id",
		"Mime-Version",
		"Pragma",
		"Received",
		"Referer",
		"Return-Path",
		"Server",
		"Set-Cookie",
		"Subject",
		"To",
		"User-Agent",
		"Via",
		"X-Forwarded-For",
		"X-Imforwards",
		"X-Powered-By",
	} {
		commonHeader[v] = v
	}
}
