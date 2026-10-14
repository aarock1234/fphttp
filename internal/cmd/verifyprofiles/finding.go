package main

import (
	"cmp"
	"fmt"
	"io"
	"slices"
)

// findingKind classifies a finding. Its value starts each printed line.
type findingKind string

const (
	// findingProfile is a cataloged release NewProfile cannot serve.
	findingProfile findingKind = "PROFILE ERROR"

	// findingNoSpan is a generated build newer than every hand-written span.
	findingNoSpan findingKind = "NO SPAN"

	// findingMismatch is a wire feature whose source value differs from the
	// catalog's.
	findingMismatch findingKind = "MISMATCH"

	// findingDerivation is source that could not be fetched or recognized.
	findingDerivation findingKind = "DERIVATION ERROR"
)

// findingOrder lists the kinds in the order findings are printed.
var findingOrder = []findingKind{
	findingProfile,
	findingNoSpan,
	findingMismatch,
	findingDerivation,
}

// finding is one problem the verification found.
type finding struct {
	kind findingKind

	// subject names what the finding is about, such as "chrome 130 on
	// windows, mac, linux (source 130.0.6723.119, wire chromium-124)".
	subject string

	// detail describes the problem.
	detail string
}

// String formats the finding as one printed line.
func (f finding) String() string {
	return string(f.kind) + " " + f.subject + ": " + f.detail
}

// compareFindings orders findings by kind, then subject, then detail.
func compareFindings(a, b finding) int {
	order := cmp.Compare(slices.Index(findingOrder, a.kind), slices.Index(findingOrder, b.kind))
	if order != 0 {
		return order
	}

	if order := cmp.Compare(a.subject, b.subject); order != 0 {
		return order
	}

	return cmp.Compare(a.detail, b.detail)
}

// printFindings writes every finding to w, one per line, in a stable order.
func printFindings(w io.Writer, findings []finding) error {
	sorted := slices.Clone(findings)
	slices.SortFunc(sorted, compareFindings)

	for _, problem := range sorted {
		if _, err := fmt.Fprintln(w, problem); err != nil {
			return fmt.Errorf("write findings: %w", err)
		}
	}

	return nil
}
