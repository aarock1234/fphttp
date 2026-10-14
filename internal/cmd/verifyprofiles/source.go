package main

import (
	"context"
	"fmt"
)

// sourceRevision is one tagged revision of a browser's source repository.
// Its files are read from the first mirror that has them.
type sourceRevision struct {
	// name identifies the revision in errors, such as "chromium
	// 152.0.7977.85".
	name string

	// mirrors are URL prefixes ending in a slash, tried in order. A later
	// mirror is tried only when an earlier one has no such file.
	mirrors []string
}

// sourceFiles holds source file text by repository path.
type sourceFiles map[string]string

// fetchFile returns the text of one file of revision.
func (f *fetcher) fetchFile(ctx context.Context, revision sourceRevision, path string) (string, error) {
	var notFound error

	for _, mirror := range revision.mirrors {
		body, err := f.fetch(ctx, mirror+path)
		if err == nil {
			return string(body), nil
		}

		if !isNotFound(err) {
			return "", fmt.Errorf("%s %s: %w", revision.name, path, err)
		}

		notFound = err
	}

	return "", fmt.Errorf("%s %s: %w", revision.name, path, notFound)
}

// fetchFiles returns the text of every path of revision, or the first
// failure.
func (f *fetcher) fetchFiles(ctx context.Context, revision sourceRevision, paths []string) (sourceFiles, error) {
	files := make(sourceFiles, len(paths))

	for _, path := range paths {
		text, err := f.fetchFile(ctx, revision, path)
		if err != nil {
			return nil, err
		}

		files[path] = text
	}

	return files, nil
}
