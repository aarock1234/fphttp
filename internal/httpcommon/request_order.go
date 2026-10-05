package httpcommon

import (
	"cmp"
	"slices"
	"strings"
)

type requestHeaderField struct {
	name  string
	value string
}

func orderRequestHeaders(enumerate func(func(string, string)), param EncodeHeadersParam) func(func(string, string)) {
	var pseudoHeaders, headers []requestHeaderField
	enumerate(func(name, value string) {
		field := requestHeaderField{
			name:  name,
			value: value,
		}
		if strings.HasPrefix(name, ":") {
			pseudoHeaders = append(pseudoHeaders, field)
		} else {
			headers = append(headers, field)
		}
	})

	if len(param.PseudoHeaderOrder) > 0 {
		ranks := headerRanks(param.PseudoHeaderOrder)
		slices.SortStableFunc(pseudoHeaders, func(a, b requestHeaderField) int {
			rankA, rankB := ranks[a.name], ranks[b.name]
			if rankA == 0 {
				rankA = len(ranks) + 1
			}
			if rankB == 0 {
				rankB = len(ranks) + 1
			}

			return cmp.Compare(rankA, rankB)
		})
	}
	if param.HeaderOrder != nil {
		ranks := headerRanks(param.HeaderOrder)
		slices.SortStableFunc(headers, func(a, b requestHeaderField) int {
			nameA := strings.ToLower(a.name)
			nameB := strings.ToLower(b.name)
			rankA, rankB := ranks[nameA], ranks[nameB]
			if rankA == 0 {
				rankA = len(ranks) + 1
			}
			if rankB == 0 {
				rankB = len(ranks) + 1
			}
			if result := cmp.Compare(rankA, rankB); result != 0 {
				return result
			}

			return strings.Compare(nameA, nameB)
		})
	}

	return func(write func(string, string)) {
		for _, field := range pseudoHeaders {
			write(field.name, field.value)
		}
		for _, field := range headers {
			write(field.name, field.value)
		}
	}
}

func headerRanks(order []string) map[string]int {
	ranks := make(map[string]int, len(order))
	for i, name := range order {
		ranks[strings.ToLower(name)] = i + 1
	}

	return ranks
}
