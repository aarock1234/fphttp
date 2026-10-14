package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// trustAnchorPattern matches one trust anchor ID in the Chrome Root Store
// text proto, written as escaped bytes such as "\x2b\x06\x01".
var trustAnchorPattern = regexp.MustCompile(`trust_anchor_id:\s*"((?:\\x[a-fA-F0-9]{2})+)"`)

// fetchTrustAnchorIDs returns the Trust Anchor IDs of the root store bundled
// with a Chromium revision, sorted bytewise as the catalog stores them.
// Chrome iterates an unordered set, so only the set is meaningful.
func fetchTrustAnchorIDs(ctx context.Context, sources *fetcher, revision sourceRevision) ([][]byte, error) {
	rootStore, err := sources.fetchFile(ctx, revision, chromiumRootStorePath)
	if err != nil {
		return nil, err
	}

	var ids [][]byte

	for _, match := range trustAnchorPattern.FindAllStringSubmatch(rootStore, -1) {
		id, err := hex.DecodeString(strings.ReplaceAll(match[1], `\x`, ""))
		if err != nil {
			return nil, fmt.Errorf("decode trust anchor id: %w", err)
		}

		ids = append(ids, id)
	}

	if len(ids) == 0 {
		return nil, errors.New("trust anchor ids are enabled, but the root store lists none")
	}

	slices.SortFunc(ids, bytes.Compare)

	return ids, nil
}

// describeTrustAnchors summarizes a sorted Trust Anchor ID list for
// comparison: its length and a short digest of its contents.
func describeTrustAnchors(ids [][]byte) string {
	if len(ids) == 0 {
		return "none"
	}

	digest := sha256.New()
	for _, id := range ids {
		digest.Write([]byte{byte(len(id))})
		digest.Write(id)
	}

	return fmt.Sprintf("%d ids (%x)", len(ids), digest.Sum(nil)[:4])
}
