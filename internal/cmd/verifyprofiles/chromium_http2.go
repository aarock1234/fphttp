package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// initialHTTP2Window is the connection window every HTTP/2 connection starts
// with (RFC 9113, section 6.9.2). The connection WINDOW_UPDATE raises it to
// the browser's session window.
const initialHTTP2Window = 65535

// spdyConstantPattern matches a kSpdy constant defined as a product of
// integers, such as "kSpdyMaxHeaderTableSize = 64 * 1024;".
var spdyConstantPattern = regexp.MustCompile(`\b(kSpdy\w+)\s*=\s*([0-9][0-9\s*]*);`)

// chromiumHTTP2 is the HTTP/2 preface a Chromium build sends, as derived
// from its network session constants.
type chromiumHTTP2 struct {
	headerTableSize      uint32
	enablePush           uint32
	initialWindowSize    uint32
	maxHeaderListSize    uint32
	connectionFlow       uint32
	maxConcurrentStreams uint32
}

// chromiumHTTP2Forms lists source text, compared without whitespace, that
// the derivation needs to hold: the defaults that would add SETTINGS
// GREASE, end streams with an empty DATA frame, or send PRIORITY_UPDATE,
// and the session code that sends only non-default settings followed by
// one connection WINDOW_UPDATE.
var chromiumHTTP2Forms = []struct {
	path string
	form string
}{
	{
		path: chromiumSessionHeaderPath,
		form: "enable_http2_settings_grease=false;",
	},
	{
		path: chromiumSessionHeaderPath,
		form: "http2_end_stream_with_data_frame=false;",
	},
	{
		path: chromiumSessionHeaderPath,
		form: "enable_priority_update=false;",
	},
	{
		path: chromiumSessionPath,
		form: "spdy_session_max_recv_window_size(kSpdySessionMaxRecvWindowSize)",
	},
	{
		path: chromiumSpdySessionPath,
		form: "IsSpdySettingAtDefaultInitialValue(setting.first,setting.second)",
	},
	{
		path: chromiumSpdySessionPath,
		form: "settings_map.insert(setting)",
	},
	{
		path: chromiumSpdySessionPath,
		form: "session_max_recv_window_size_-session_recv_window_size_",
	},
	{
		path: chromiumSpdySessionPath,
		form: "CreateSettings(settings_map)",
	},
}

// deriveChromiumHTTP2 reads the HTTP/2 SETTINGS and connection window from
// the network session constants. MAX_CONCURRENT_STREAMS is sent only while
// the session still advertises its pushed stream limit (through 116).
func deriveChromiumHTTP2(files sourceFiles) (chromiumHTTP2, error) {
	if err := checkHTTP2Forms(files); err != nil {
		return chromiumHTTP2{}, err
	}

	constants, err := spdyConstants(files[chromiumSessionPath] + files[chromiumSessionHeaderPath])
	if err != nil {
		return chromiumHTTP2{}, err
	}

	reader := constantReader{
		constants: constants,
	}

	http2 := chromiumHTTP2{
		headerTableSize:   reader.value("kSpdyMaxHeaderTableSize"),
		enablePush:        reader.value("kSpdyDisablePush"),
		initialWindowSize: reader.value("kSpdyStreamMaxRecvWindowSize"),
		maxHeaderListSize: reader.value("kSpdyMaxHeaderListSize"),
	}

	sessionWindow := reader.value("kSpdySessionMaxRecvWindowSize")

	if strings.Contains(files[chromiumSessionPath], "SETTINGS_MAX_CONCURRENT_STREAMS") {
		http2.maxConcurrentStreams = reader.value("kSpdyMaxConcurrentPushedStreams")
	}

	if reader.err != nil {
		return chromiumHTTP2{}, reader.err
	}

	if sessionWindow > initialHTTP2Window {
		http2.connectionFlow = sessionWindow - initialHTTP2Window
	}

	return http2, nil
}

// checkHTTP2Forms fails when a file lacks one of chromiumHTTP2Forms.
func checkHTTP2Forms(files sourceFiles) error {
	compact := make(map[string]string)

	for _, requirement := range chromiumHTTP2Forms {
		text, ok := compact[requirement.path]
		if !ok {
			text = strings.Join(strings.Fields(files[requirement.path]), "")
			compact[requirement.path] = text
		}

		if !strings.Contains(text, requirement.form) {
			return fmt.Errorf("unrecognized HTTP/2 source: %s lacks %s", requirement.path, requirement.form)
		}
	}

	return nil
}

// spdyConstants evaluates every kSpdy integer constant in source.
func spdyConstants(source string) (map[string]uint32, error) {
	constants := make(map[string]uint32)

	for _, match := range spdyConstantPattern.FindAllStringSubmatch(source, -1) {
		value, err := evaluateProduct(match[2])
		if err != nil {
			return nil, fmt.Errorf("constant %s: %w", match[1], err)
		}

		constants[match[1]] = value
	}

	return constants, nil
}

// evaluateProduct evaluates a product of unsigned integers, such as
// "15 * 1024 * 1024".
func evaluateProduct(expression string) (uint32, error) {
	product := uint64(1)

	for factor := range strings.SplitSeq(expression, "*") {
		value, err := strconv.ParseUint(strings.TrimSpace(factor), 10, 32)
		if err != nil {
			return 0, fmt.Errorf("parse %q: %w", expression, err)
		}

		product *= value
		if product > 1<<32-1 {
			return 0, fmt.Errorf("%q overflows 32 bits", expression)
		}
	}

	return uint32(product), nil
}

// constantReader looks up kSpdy constants. After the first missing constant
// every lookup returns zero and err keeps the failure.
type constantReader struct {
	constants map[string]uint32
	err       error
}

// value returns the constant name.
func (r *constantReader) value(name string) uint32 {
	if r.err != nil {
		return 0
	}

	value, ok := r.constants[name]
	if !ok {
		r.err = fmt.Errorf("unrecognized HTTP/2 source: no constant %s", name)
	}

	return value
}
