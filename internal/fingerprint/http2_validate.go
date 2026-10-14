package fingerprint

import (
	"errors"
	"fmt"
	"math"
)

// Bounds of HTTP/2 SETTINGS values (RFC 9113, section 6.5.2).
const (
	minMaxFrameSize = 16384
	maxMaxFrameSize = 16777215

	// initialConnectionWindow is the connection flow-control window every
	// HTTP/2 connection starts with, before WINDOW_UPDATE.
	initialConnectionWindow = 65535
)

// Validate checks the dependency's range and, when known, the stream ID.
func (p Priority) Validate(streamID uint32) error {
	if !p.Enabled {
		return nil
	}

	if p.StreamDep > math.MaxInt32 {
		return errors.New("fphttp: HEADERS priority dependency exceeds 2147483647")
	}

	if streamID != 0 && p.StreamDep == streamID {
		return errors.New("fphttp: a HEADERS frame cannot depend on its own stream")
	}

	return nil
}

// Validate rejects configurations that cannot be sent or honored safely.
// It returns every problem joined with errors.Join.
func (h HTTP2) Validate() error {
	return errors.Join(
		h.validateSettings(),
		h.validateStreams(),
		h.validatePriorityFrames(),
		h.validatePrioritySignals(),
	)
}

// validateSettings checks each SETTINGS parameter, rejects duplicates, and
// requires server push to be disabled explicitly.
func (h HTTP2) validateSettings() error {
	if h.Settings == nil {
		return nil
	}

	var problems []error
	seen := make(map[SettingID]bool, len(h.Settings))

	for _, setting := range h.Settings {
		if seen[setting.ID] {
			problems = append(problems, fmt.Errorf("fphttp: Profile.HTTP2.Settings contain %v twice", setting.ID))
		}

		seen[setting.ID] = true
		problems = append(problems, validateSetting(setting))
	}

	if !seen[SettingEnablePush] {
		problems = append(problems, errors.New("fphttp: Profile.HTTP2.Settings must include ENABLE_PUSH = 0"))
	}

	return errors.Join(problems...)
}

// validateSetting checks the value of one SETTINGS parameter. Parameters
// without a constrained value are accepted as they are.
func validateSetting(setting Setting) error {
	switch setting.ID {
	case SettingEnablePush:
		if setting.Val != 0 {
			return errors.New("fphttp: Profile.HTTP2 ENABLE_PUSH must be 0; server push is unsupported")
		}

	case SettingInitialWindowSize:
		if setting.Val == 0 || setting.Val > math.MaxInt32 {
			return errors.New("fphttp: Profile.HTTP2 INITIAL_WINDOW_SIZE must be between 1 and 2147483647")
		}

	case SettingMaxFrameSize:
		if setting.Val < minMaxFrameSize || setting.Val > maxMaxFrameSize {
			return errors.New("fphttp: Profile.HTTP2 MAX_FRAME_SIZE must be between 16384 and 16777215")
		}

	case SettingMaxHeaderListSize:
		if setting.Val == 0 {
			return errors.New("fphttp: Profile.HTTP2 MAX_HEADER_LIST_SIZE must allow response headers")
		}

	case SettingEnableConnectProtocol, SettingNoRFC7540Priorities:
		if setting.Val > 1 {
			return fmt.Errorf("fphttp: Profile.HTTP2 %v must be 0 or 1", setting.ID)
		}
	}

	return nil
}

// validateStreams checks the connection window, the first stream ID, and the
// default HEADERS priority against that first stream.
func (h HTTP2) validateStreams() error {
	var problems []error

	if h.ConnectionFlow > math.MaxInt32-initialConnectionWindow {
		problems = append(problems, errors.New("fphttp: Profile.HTTP2.ConnectionFlow plus the initial window exceeds 2147483647"))
	}

	if h.InitialStreamID != 0 && (h.InitialStreamID%2 == 0 || h.InitialStreamID > math.MaxInt32) {
		problems = append(problems, errors.New("fphttp: Profile.HTTP2.InitialStreamID must be an odd 31-bit stream ID"))
	}

	problems = append(problems, h.HeaderPriority.Validate(h.firstStreamID()))

	return errors.Join(problems...)
}

// validatePriorityFrames checks the stream and dependency of every
// standalone PRIORITY frame.
func (h HTTP2) validatePriorityFrames() error {
	var problems []error

	for index, frame := range h.InitPriorityFrames {
		if frame.StreamID == 0 || frame.StreamID > math.MaxInt32 {
			problems = append(problems, fmt.Errorf("fphttp: Profile.HTTP2.InitPriorityFrames[%d] requires a non-zero 31-bit StreamID", index))
		}

		if frame.StreamDep > math.MaxInt32 || frame.StreamDep == frame.StreamID {
			problems = append(problems, fmt.Errorf("fphttp: Profile.HTTP2.InitPriorityFrames[%d] has an invalid StreamDep", index))
		}
	}

	return errors.Join(problems...)
}

// validatePrioritySignals rejects standalone PRIORITY frames on a connection
// that announces NO_RFC7540_PRIORITIES = 1.
//
// An enabled HeaderPriority is accepted together with the setting: Firefox
// 132 and later announce it and still set the PRIORITY flag on every
// HEADERS frame, so a browser-faithful profile needs both.
func (h HTTP2) validatePrioritySignals() error {
	disabled, _ := h.SettingValue(SettingNoRFC7540Priorities)
	if disabled != 1 || len(h.InitPriorityFrames) == 0 {
		return nil
	}

	return errors.New("fphttp: Profile.HTTP2 NO_RFC7540_PRIORITIES = 1 conflicts with InitPriorityFrames")
}

// firstStreamID returns the stream ID of the first request.
func (h HTTP2) firstStreamID() uint32 {
	if h.InitialStreamID == 0 {
		return 1
	}

	return h.InitialStreamID
}
