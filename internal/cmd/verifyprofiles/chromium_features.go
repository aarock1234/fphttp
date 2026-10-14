package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aarock1234/fphttp/v2/internal/catalog"
)

// featureMacro starts every Chromium feature declaration.
const featureMacro = "BASE_FEATURE("

// featureOverrides holds feature defaults that replace Chromium's, keyed by
// feature name without the k prefix, as Brave sets them.
type featureOverrides map[string]bool

// featureReader reads compiled feature defaults from net/base/features.cc
// for one platform.
//
// After its first failure every read returns false and err keeps that
// failure, so a derivation can read all of its features and check once.
type featureReader struct {
	source    string
	platform  catalog.Platform
	overrides featureOverrides
	err       error
}

// enabled returns whether the feature name is enabled by default on the
// reader's platform.
//
// Chromium declares a feature as BASE_FEATURE(kName, ...) or, from 141 on,
// as BASE_FEATURE(Name, ...); both are recognized. A feature the source does
// not declare reports absent, which the caller derives from the code path
// Chromium takes without the feature, as after a feature launches and its
// flag is removed. An override replaces the declaration.
func (r *featureReader) enabled(name string, absent bool) bool {
	if r.err != nil {
		return false
	}

	if value, ok := r.overrides[name]; ok {
		return value
	}

	value, err := featureDefault(r.source, name, r.platform, absent)
	if err != nil {
		r.err = err

		return false
	}

	return value
}

// featureDefault returns the compiled default state of the feature name on
// platform, or absent when source does not declare it.
func featureDefault(source, name string, platform catalog.Platform, absent bool) (bool, error) {
	start := findFeature(source, name)
	if start < 0 {
		return absent, nil
	}

	declaration, err := compiledDeclaration(source[start:], platform)
	if err != nil {
		return false, fmt.Errorf("feature %s: %w", name, err)
	}

	enabled := strings.Contains(declaration, "FEATURE_ENABLED_BY_DEFAULT")
	disabled := strings.Contains(declaration, "FEATURE_DISABLED_BY_DEFAULT")

	if enabled == disabled {
		return false, fmt.Errorf("feature %s: unrecognized default state", name)
	}

	return enabled, nil
}

// findFeature returns the offset of the declaration of the feature name in
// source, written with or without the k prefix, or -1 when there is none.
func findFeature(source, name string) int {
	offset := 0

	for {
		found := strings.Index(source[offset:], featureMacro)
		if found < 0 {
			return -1
		}

		start := offset + found
		offset = start + len(featureMacro)

		if declaresFeature(source[offset:], name) {
			return start
		}
	}
}

// declaresFeature reports whether arguments, the text after "BASE_FEATURE(",
// starts with the identifier name or kName followed by a comma.
func declaresFeature(arguments, name string) bool {
	rest := strings.TrimLeft(arguments, " \t\r\n")
	rest = strings.TrimPrefix(rest, "k")

	rest, ok := strings.CutPrefix(rest, name)
	if !ok {
		return false
	}

	return strings.HasPrefix(strings.TrimLeft(rest, " \t\r\n"), ",")
}

// compiledDeclaration returns the lines of the declaration at the start of
// text that compile on platform. Preprocessor branches are resolved and the
// inactive ones dropped. The declaration ends at the first ");" once every
// conditional it opened is closed, so a declaration with a ");" in each
// branch is read to its #endif rather than into the next declaration.
func compiledDeclaration(text string, platform catalog.Platform) (string, error) {
	var (
		declaration strings.Builder
		branches    conditionStack
		closed      bool
	)

	for line := range strings.Lines(text) {
		directive := strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(directive, "#"):
			if err := branches.apply(directive, platform); err != nil {
				return "", err
			}

		case branches.active():
			declaration.WriteString(line)
			closed = closed || strings.Contains(line, ");")
		}

		if closed && len(branches) == 0 {
			return declaration.String(), nil
		}
	}

	return "", errors.New("unterminated declaration")
}

// conditionFrame is one open #if block.
type conditionFrame struct {
	// taken reports whether a branch of the block has been active.
	taken bool

	// current reports whether the branch being read is active.
	current bool
}

// conditionStack holds the open #if blocks, outermost first.
type conditionStack []conditionFrame

// active reports whether every open block is in an active branch.
func (s conditionStack) active() bool {
	for _, frame := range s {
		if !frame.current {
			return false
		}
	}

	return true
}

// apply updates the stack for one preprocessor directive.
func (s *conditionStack) apply(directive string, platform catalog.Platform) error {
	keyword, expression := splitDirective(directive)

	if keyword == "#if" {
		value, err := evaluateCondition(expression, platform)
		if err != nil {
			return err
		}

		*s = append(*s, conditionFrame{
			taken:   value,
			current: value,
		})

		return nil
	}

	if len(*s) == 0 {
		return fmt.Errorf("unexpected preprocessor directive %q", directive)
	}

	top := &(*s)[len(*s)-1]

	switch keyword {
	case "#elif":
		value, err := evaluateCondition(expression, platform)
		if err != nil {
			return err
		}

		top.current = value && !top.taken
		top.taken = top.taken || value

	case "#else":
		top.current = !top.taken
		top.taken = true

	case "#endif":
		*s = (*s)[:len(*s)-1]

	default:
		return fmt.Errorf("unsupported preprocessor directive %q", directive)
	}

	return nil
}

// splitDirective splits a preprocessor line into its keyword, such as
// "#if", and its expression without a trailing comment.
func splitDirective(directive string) (string, string) {
	end := strings.IndexAny(directive, " \t")
	if end < 0 {
		return directive, ""
	}

	expression, _, _ := strings.Cut(directive[end:], "//")

	return directive[:end], strings.TrimSpace(expression)
}

// evaluateCondition evaluates a preprocessor condition of BUILDFLAG terms,
// each optionally negated with "!", joined by "||" and "&&". "&&" binds
// tighter, as in C. Parentheses around terms are not supported.
func evaluateCondition(expression string, platform catalog.Platform) (bool, error) {
	for alternative := range strings.SplitSeq(expression, "||") {
		matched := true

		for term := range strings.SplitSeq(alternative, "&&") {
			value, err := evaluateTerm(term, platform)
			if err != nil {
				return false, fmt.Errorf("condition %q: %w", strings.TrimSpace(expression), err)
			}

			matched = matched && value
		}

		if matched {
			return true, nil
		}
	}

	return false, nil
}

// evaluateTerm evaluates one BUILDFLAG(NAME) or !BUILDFLAG(NAME) term.
func evaluateTerm(term string, platform catalog.Platform) (bool, error) {
	term = strings.TrimSpace(term)

	negated := strings.HasPrefix(term, "!")
	term = strings.TrimSpace(strings.TrimPrefix(term, "!"))

	name, ok := strings.CutPrefix(term, "BUILDFLAG(")
	if !ok {
		return false, fmt.Errorf("unsupported term %q", term)
	}

	name, ok = strings.CutSuffix(name, ")")
	if !ok {
		return false, fmt.Errorf("unsupported term %q", term)
	}

	value, err := buildFlag(name, platform)
	if err != nil {
		return false, err
	}

	return value != negated, nil
}

// buildFlag returns the value of a Chromium build flag in the official
// browser build for platform.
func buildFlag(name string, platform catalog.Platform) (bool, error) {
	switch name {
	case "IS_WIN":
		return platform == catalog.Windows, nil
	case "IS_MAC", "IS_APPLE":
		return platform == catalog.Mac, nil
	case "IS_LINUX":
		return platform == catalog.Linux, nil
	case "IS_ANDROID":
		return platform == catalog.Android, nil
	case "IS_POSIX":
		return platform != catalog.Windows, nil
	case "IS_IOS", "IS_CHROMEOS", "IS_FUCHSIA", "CRONET_BUILD":
		return false, nil
	default:
		return false, fmt.Errorf("unrecognized build flag %s", name)
	}
}
