package http

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// clientInit holds the values extracted from a fresh HTTP/2 client
// connection's initialization frames.
type clientInit struct {
	settings   []H2Setting
	connFlow   uint32
	priorities []H2PriorityFrame
}

// readClientInit drains a fresh HTTP/2 client connection's initialization
// frames from the server side of conn: the client preface followed by the
// SETTINGS, WINDOW_UPDATE, and any PRIORITY frames, in order. Each frame's
// data is extracted immediately, since the framer reuses frame buffers.
func readClientInit(t *testing.T, conn net.Conn, wantPriority int) clientInit {
	t.Helper()

	preface := make([]byte, len(http2clientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		t.Fatalf("reading client preface: %v", err)
	}
	if !bytes.Equal(preface, http2clientPreface) {
		t.Fatalf("client preface = %q, want %q", preface, http2clientPreface)
	}

	fr := http2NewFramer(conn, conn)

	settings, ok := mustReadFrame(t, fr).(*http2SettingsFrame)
	if !ok {
		t.Fatalf("first frame is not SETTINGS")
	}
	var init clientInit
	if err := settings.ForeachSetting(func(s http2Setting) error {
		init.settings = append(init.settings, H2Setting{ID: H2SettingID(s.ID), Val: s.Val})
		return nil
	}); err != nil {
		t.Fatalf("ForeachSetting: %v", err)
	}

	wu, ok := mustReadFrame(t, fr).(*http2WindowUpdateFrame)
	if !ok {
		t.Fatalf("second frame is not WINDOW_UPDATE")
	}
	init.connFlow = wu.Increment

	for range wantPriority {
		pf, ok := mustReadFrame(t, fr).(*http2PriorityFrame)
		if !ok {
			t.Fatalf("expected PRIORITY frame, got %T", pf)
		}
		init.priorities = append(init.priorities, H2PriorityFrame{
			StreamID:  pf.StreamID,
			StreamDep: pf.StreamDep,
			Exclusive: pf.Exclusive,
			Weight:    pf.Weight,
		})
	}

	return init
}

func mustReadFrame(t *testing.T, fr *http2Framer) http2Frame {
	t.Helper()
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("reading frame: %v", err)
	}

	return f
}

// newFingerprintClientConn starts a client connection for fp over an in-memory
// pipe and returns it along with the extracted initialization frames. The
// frames are written eagerly, so the server end is drained before returning.
func newFingerprintClientConn(t *testing.T, fp *Fingerprint, wantPriority int) (*http2ClientConn, clientInit) {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	tr := &Transport{Fingerprint: fp}
	h2 := &http2Transport{t1: tr, fingerprint: fp}

	type result struct {
		cc  *http2ClientConn
		err error
	}
	done := make(chan result, 1)
	go func() {
		cc, err := h2.newClientConn(client, true, nil)
		done <- result{cc, err}
	}()

	init := readClientInit(t, server, wantPriority)

	res := <-done
	if res.err != nil {
		t.Fatalf("newClientConn: %v", res.err)
	}

	return res.cc, init
}

func TestFingerprint_H2SettingsFrame(t *testing.T) {
	fp := Chrome()
	cc, init := newFingerprintClientConn(t, fp, 0)

	want := fp.H2.Settings
	if len(init.settings) != len(want) {
		t.Fatalf("SETTINGS count = %d, want %d (%v)", len(init.settings), len(want), init.settings)
	}
	for i := range want {
		if init.settings[i] != want[i] {
			t.Errorf("SETTINGS[%d] = %+v, want %+v", i, init.settings[i], want[i])
		}
	}

	if init.connFlow != fp.H2.ConnectionFlow {
		t.Errorf("WINDOW_UPDATE increment = %d, want %d", init.connFlow, fp.H2.ConnectionFlow)
	}

	// Regression: the advertised INITIAL_WINDOW_SIZE must equal the window we
	// actually grant per stream, otherwise the server can legally overrun our
	// receive window and trip FLOW_CONTROL_ERROR.
	var advertised uint32
	for _, s := range want {
		if s.ID == H2SettingInitialWindowSize {
			advertised = s.Val
		}
	}
	if advertised == 0 {
		t.Fatal("Chrome profile is expected to advertise INITIAL_WINDOW_SIZE")
	}
	if int32(advertised) != cc.initialStreamRecvWindowSize {
		t.Errorf("advertised INITIAL_WINDOW_SIZE = %d, but stream recv window = %d",
			advertised, cc.initialStreamRecvWindowSize)
	}
}

func TestFingerprint_H2InitPriorityFrames(t *testing.T) {
	fp := Firefox()
	want := fp.H2.InitPriorityFrames
	_, init := newFingerprintClientConn(t, fp, len(want))

	if len(init.priorities) != len(want) {
		t.Fatalf("PRIORITY frame count = %d, want %d", len(init.priorities), len(want))
	}
	for i, pf := range init.priorities {
		if pf != want[i] {
			t.Errorf("PRIORITY[%d] = %+v, want %+v", i, pf, want[i])
		}
	}
}

func TestFingerprint_H2PseudoHeaderOrder(t *testing.T) {
	for _, fp := range []*Fingerprint{Chrome(), Firefox(), Safari(), Edge(), Brave()} {
		req, err := NewRequest("GET", "https://example.com/path?q=1", nil)
		if err != nil {
			t.Fatal(err)
		}

		var pseudo []string
		if _, err := http2encodeRequestHeaders(req, false, 0, fp, func(name, value string) {
			if len(name) > 0 && name[0] == ':' {
				pseudo = append(pseudo, name)
			}
		}); err != nil {
			t.Fatalf("encodeRequestHeaders: %v", err)
		}

		if len(pseudo) != len(fp.PseudoHeaderOrder) {
			t.Fatalf("pseudo count = %d, want %d", len(pseudo), len(fp.PseudoHeaderOrder))
		}
		for i, name := range fp.PseudoHeaderOrder {
			if pseudo[i] != name {
				t.Errorf("pseudo[%d] = %q, want %q (order %v)", i, pseudo[i], name, pseudo)
			}
		}
	}
}

func TestFingerprint_H2HeaderOrder(t *testing.T) {
	fp := &Fingerprint{
		HeaderOrder: []string{"Accept-Language", "Accept", "Accept-Encoding"},
	}

	req, err := NewRequest("GET", "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Accept-Language", "en-US")

	var regular []string
	if _, err := http2encodeRequestHeaders(req, false, 0, fp, func(name, value string) {
		if len(name) > 0 && name[0] == ':' {
			return
		}
		regular = append(regular, name)
	}); err != nil {
		t.Fatalf("encodeRequestHeaders: %v", err)
	}

	// The three ordered headers must come first, lowercased, in the given order.
	want := []string{"accept-language", "accept", "accept-encoding"}
	if len(regular) < len(want) {
		t.Fatalf("emitted %d regular headers, want at least %d (%v)", len(regular), len(want), regular)
	}
	for i, name := range want {
		if regular[i] != name {
			t.Errorf("regular[%d] = %q, want %q (order %v)", i, regular[i], name, regular)
		}
	}
}
