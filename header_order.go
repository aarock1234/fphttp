package http

import (
	"io"
	"slices"

	"github.com/aarock1234/fphttp/v2/httptrace"
)

// writeSubsetOrdered writes the fields order lists first, in that order,
// followed by the remaining fields in lexical order. Values keep their order
// within each field.
func (h Header) writeSubsetOrdered(w io.Writer, exclude map[string]bool, order []string, trace *httptrace.ClientTrace) error {
	return h.writeSubsetOrderedCase(w, exclude, order, trace, nil)
}

// writeSubsetOrderedCase is writeSubsetOrdered with HTTP/1.1 spellings from
// names. Order entries match keys ignoring case.
func (h Header) writeSubsetOrderedCase(w io.Writer, exclude map[string]bool, order []string, trace *httptrace.ClientTrace, names map[string]string) error {
	kvs, sorter := h.sortedKeyValues(exclude)
	defer headerSorterPool.Put(sorter)

	ranks := headerOrderRanks(kvs, order)
	slices.SortStableFunc(kvs, func(a, b keyValues) int {
		return ranks[a.key] - ranks[b.key]
	})

	return writeHeaderKeyValuesCase(w, kvs, trace, names)
}

// headerOrderRanks maps each key in kvs to its position in order, matching
// names ignoring case. Keys the order does not list rank after every listed
// key; the first of two entries naming one field wins.
func headerOrderRanks(kvs []keyValues, order []string) map[string]int {
	positions := make(map[string]int, len(order))
	for index, name := range order {
		key := CanonicalHeaderKey(name)
		if _, listed := positions[key]; !listed {
			positions[key] = index + 1
		}
	}

	ranks := make(map[string]int, len(kvs))
	for _, kv := range kvs {
		rank, listed := positions[CanonicalHeaderKey(kv.key)]
		if !listed {
			rank = len(order) + 1
		}

		ranks[kv.key] = rank
	}

	return ranks
}
