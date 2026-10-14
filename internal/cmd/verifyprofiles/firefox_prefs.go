package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// preferenceReader reads Firefox preference defaults for desktop or
// Android: GeckoView's geckoview-prefs.js overrides on Android first, then
// the build defaults in StaticPrefList.yaml.
//
// After its first failure every read returns a zero value and err keeps
// that failure, so a derivation can read all of its preferences and check
// once.
type preferenceReader struct {
	// static is StaticPrefList.yaml.
	static string

	// geckoView is geckoview-prefs.js, or "" on desktop.
	geckoView string

	android bool
	err     error
}

// boolean returns a boolean preference, or absent when no default is
// declared.
func (r *preferenceReader) boolean(name string, absent bool) bool {
	text, found := r.value(name)
	if !found {
		return absent
	}

	value, err := strconv.ParseBool(text)
	if err != nil {
		r.fail(fmt.Errorf("preference %s: %q is not a boolean", name, text))

		return false
	}

	return value
}

// requiredBoolean returns a boolean preference that must be declared.
func (r *preferenceReader) requiredBoolean(name string) bool {
	r.require(name)

	return r.boolean(name, false)
}

// number returns an unsigned 32-bit preference, or absent when no default
// is declared.
func (r *preferenceReader) number(name string, absent uint32) uint32 {
	text, found := r.value(name)
	if !found {
		return absent
	}

	value, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		r.fail(fmt.Errorf("preference %s: %q is not an unsigned number", name, text))

		return 0
	}

	return uint32(value)
}

// requiredNumber returns an unsigned 32-bit preference that must be
// declared.
func (r *preferenceReader) requiredNumber(name string) uint32 {
	r.require(name)

	return r.number(name, 0)
}

// require fails the reader when name has no default.
func (r *preferenceReader) require(name string) {
	if _, found := r.value(name); !found {
		r.fail(fmt.Errorf("missing Firefox preference %s", name))
	}
}

// value returns the default of name and whether one is declared.
func (r *preferenceReader) value(name string) (string, bool) {
	if r.err != nil {
		return "", false
	}

	if r.android {
		value, found, err := geckoViewPreference(r.geckoView, name)
		if err != nil {
			r.fail(err)

			return "", false
		}

		if found {
			return value, true
		}
	}

	value, found, err := staticPreference(r.static, name, r.android)
	if err != nil {
		r.fail(err)

		return "", false
	}

	return value, found
}

// fail keeps the first failure.
func (r *preferenceReader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

// staticPreference returns the release-build default of name in
// StaticPrefList.yaml, and whether the file declares it.
//
// It recognizes only the conditional forms the read preferences use; any
// other form fails, because a new condition needs review before its value
// can be trusted.
func staticPreference(source, name string, android bool) (string, bool, error) {
	const entryPrefix = "- name: "

	start := strings.Index(source, entryPrefix+name+"\n")
	if start < 0 {
		return "", false, nil
	}

	block := source[start+len(entryPrefix):]
	if end := strings.Index(block, "\n"+entryPrefix); end >= 0 {
		block = block[:end]
	}

	value, err := activeValue(block, android)
	if err != nil {
		return "", false, fmt.Errorf("Firefox preference %s: %w", name, err)
	}

	return value, true, nil
}

// activeValue returns the value line of a StaticPrefList.yaml entry that a
// release build on the platform compiles.
func activeValue(block string, android bool) (string, error) {
	var (
		selected    string
		active      = true
		conditional bool
	)

	for line := range strings.Lines(block) {
		line = strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(line, "#if"):
			if conditional {
				return "", fmt.Errorf("nested condition %q", line)
			}

			branch, err := preferenceBranch(line, android)
			if err != nil {
				return "", err
			}

			active = branch
			conditional = true

		case strings.HasPrefix(line, "#elif"):
			return "", fmt.Errorf("unsupported condition %q", line)

		case line == "#else":
			if conditional {
				active = !active
			}

		case line == "#endif":
			active = true
			conditional = false

		case active && strings.HasPrefix(line, "value:"):
			fields := strings.Fields(strings.TrimPrefix(line, "value:"))
			if len(fields) == 0 || selected != "" {
				return "", fmt.Errorf("ambiguous value %q", line)
			}

			value, err := preferenceValue(fields[0], android)
			if err != nil {
				return "", err
			}

			selected = value
		}
	}

	if selected == "" {
		return "", errors.New("no active value")
	}

	return selected, nil
}

// preferenceBranch evaluates a StaticPrefList.yaml condition for a release
// build on desktop or Android.
func preferenceBranch(directive string, android bool) (bool, error) {
	compact := strings.Join(strings.Fields(directive), "")

	switch compact {
	case "#ifdefANDROID", "#ifdefined(ANDROID)", "#ifdefined(ANDROID)&&!defined(EARLY_BETA_OR_EARLIER)":
		return android, nil
	case "#ifndefANDROID", "#if!defined(ANDROID)":
		return !android, nil
	case "#ifdefNIGHTLY_BUILD", "#ifdefEARLY_BETA_OR_EARLIER", "#ifdefined(NIGHTLY_BUILD)", "#ifdefined(EARLY_BETA_OR_EARLIER)":
		return false, nil
	default:
		return false, fmt.Errorf("unrecognized condition %q", directive)
	}
}

// preferenceValue resolves a StaticPrefList.yaml value, including the build
// substitutions, for a release build on desktop or Android.
func preferenceValue(value string, android bool) (string, error) {
	switch value {
	case "true", "false":
		return value, nil
	case "@IS_ANDROID@":
		return strconv.FormatBool(android), nil
	case "@IS_NOT_ANDROID@":
		return strconv.FormatBool(!android), nil
	case "@IS_NIGHTLY_BUILD@", "@IS_EARLY_BETA_OR_EARLIER@":
		return "false", nil
	case "@IS_NOT_NIGHTLY_BUILD@", "@IS_NOT_EARLY_BETA_OR_EARLIER@":
		return "true", nil
	}

	if _, err := strconv.ParseUint(value, 10, 32); err != nil {
		return "", fmt.Errorf("unrecognized value %q", value)
	}

	return value, nil
}

// geckoViewPreference returns the value geckoview-prefs.js sets for name,
// and whether it sets one. A preference set inside a conditional block
// fails, because its release value needs review.
func geckoViewPreference(source, name string) (string, bool, error) {
	var (
		value string
		found bool
		depth int
	)

	setter := `pref("` + name + `",`

	for line := range strings.Lines(source) {
		line = strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(line, "#if"):
			depth++

		case strings.HasPrefix(line, "#endif"):
			depth--

		case strings.HasPrefix(line, setter):
			if depth > 0 {
				return "", false, fmt.Errorf("GeckoView preference %s is set conditionally", name)
			}

			if found {
				return "", false, fmt.Errorf("GeckoView preference %s is set twice", name)
			}

			value = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, setter), ");"))
			found = true
		}
	}

	return value, found, nil
}
