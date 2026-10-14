package http2

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
)

// This file is fphttp-only. It applies the HTTP/2 settings a server sends
// in the TLS ALPS extension, as Chromium does (SpdySession::ParseAlps and
// AlpsDecoder in net/spdy).

// applicationSettingsConn is a TLS connection that reports the application
// settings the server sent with ALPS for the negotiated protocol, such as
// the root package's uTLS connection.
type applicationSettingsConn interface {
	PeerApplicationSettings() []byte
}

// applyPeerApplicationSettings applies the SETTINGS frames a server sent in
// its ALPS extension to cc before the server's first SETTINGS frame
// arrives, so the first requests already honor them. It does nothing when
// conn reports no application settings.
//
// Chromium handles ALPS the same way: it applies each setting as if it came
// in a SETTINGS frame, never acknowledges them, and closes the connection
// with a protocol error when the payload is not a sequence of complete
// HTTP/2 frames, contains a SETTINGS acknowledgment, or contains a frame
// other than SETTINGS and extension frames. Extension frames, such as
// ACCEPT_CH, are ignored. The frames are decoded with the connection's
// own Framer rules, so a SETTINGS frame that Go rejects on the connection,
// such as one with an INITIAL_WINDOW_SIZE above 2147483647, also fails
// here; Chromium ignores that one value.
//
// It runs in newClientConn, before the read loop starts.
func (cc *ClientConn) applyPeerApplicationSettings(conn net.Conn) error {
	alpsConn, ok := conn.(applicationSettingsConn)
	if !ok {
		return nil
	}

	payload := alpsConn.PeerApplicationSettings()
	if len(payload) == 0 {
		return nil
	}

	settings, err := decodeApplicationSettings(payload)
	if err != nil {
		return fmt.Errorf("http2: invalid ALPS settings from server: %w", err)
	}

	cc.wmu.Lock()
	defer cc.wmu.Unlock()

	cc.mu.Lock()
	defer cc.mu.Unlock()

	for _, setting := range settings {
		if err := cc.applyPeerApplicationSetting(setting); err != nil {
			return fmt.Errorf("http2: invalid ALPS settings from server: %w", err)
		}
	}

	return nil
}

// decodeApplicationSettings reads the HTTP/2 frames of an ALPS payload and
// returns the settings of its SETTINGS frames in order.
func decodeApplicationSettings(payload []byte) ([]Setting, error) {
	reader := bytes.NewReader(payload)
	framer := NewFramer(io.Discard, reader)

	// Every frame must be complete, so reading stops only when the
	// payload is used up exactly; a truncated frame fails ReadFrame.
	var settings []Setting
	for reader.Len() > 0 {
		frame, err := framer.ReadFrame()
		if err != nil {
			return nil, err
		}

		switch frame := frame.(type) {
		case *SettingsFrame:
			if frame.IsAck() {
				return nil, errors.New("SETTINGS acknowledgment")
			}

			// The frame is only valid until the next ReadFrame, so its
			// settings are copied now.
			_ = frame.ForeachSetting(func(setting Setting) error {
				settings = append(settings, setting)

				return nil
			})

		case *DataFrame, *HeadersFrame, *PriorityFrame, *RSTStreamFrame, *PushPromiseFrame,
			*PingFrame, *GoAwayFrame, *WindowUpdateFrame, *ContinuationFrame:
			return nil, fmt.Errorf("forbidden %v frame", frame.Header().Type)
		}
	}

	return settings, nil
}

// applyPeerApplicationSetting applies one ALPS setting the way
// processSettingsNoWrite applies a SETTINGS frame, except for values that
// Chromium ignores rather than rejects: an out-of-range MAX_FRAME_SIZE and
// ENABLE_PUSH, which only a server may use, are skipped. The Framer has
// already rejected an out-of-range INITIAL_WINDOW_SIZE.
// ENABLE_CONNECT_PROTOCOL and NO_RFC7540_PRIORITIES values other than 0 and
// 1 fail the connection, as in Chromium. The caller holds cc.wmu and cc.mu.
func (cc *ClientConn) applyPeerApplicationSetting(setting Setting) error {
	switch setting.ID {
	case SettingMaxFrameSize:
		if setting.Valid() == nil {
			cc.maxFrameSize = setting.Val
		}

	case SettingMaxConcurrentStreams:
		cc.maxConcurrentStreams = setting.Val
		cc.alpsMaxConcurrentStreams = true

	case SettingMaxHeaderListSize:
		cc.peerMaxHeaderListSize = uint64(setting.Val)

	case SettingInitialWindowSize:
		// No stream is open yet, so no stream window can overflow.
		cc.flow.changeInitialWindowSize(int64(setting.Val))

	case SettingHeaderTableSize:
		cc.henc.SetMaxDynamicTableSize(setting.Val)
		cc.peerMaxHeaderTableSize = setting.Val

	case SettingEnableConnectProtocol:
		if err := setting.Valid(); err != nil {
			return err
		}

		cc.extendedConnectAllowed = setting.Val == 1

	case SettingNoRFC7540Priorities:
		if setting.Val > 1 {
			return ConnectionError(ErrCodeProtocol)
		}
	}

	return nil
}
