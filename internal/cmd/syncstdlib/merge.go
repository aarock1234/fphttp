package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
)

type fileChange struct {
	path    string
	content []byte // nil removes an unchanged upstream file
}

type synchronizer struct {
	repo     *upstream
	root     string
	work     string
	base     string
	revision string
}

func (s *synchronizer) stageChanges(ctx context.Context) ([]fileChange, error) {
	previous, err := s.repo.files(ctx, s.base)
	if err != nil {
		return nil, err
	}
	next, err := s.repo.files(ctx, s.revision)
	if err != nil {
		return nil, err
	}
	paths := maps.Clone(previous)
	maps.Copy(paths, next)

	var changes []fileChange
	for _, path := range slices.Sorted(maps.Keys(paths)) {
		change, err := s.mergeSource(ctx, path, previous[path], next[path])
		if err != nil {
			return nil, fmt.Errorf("sync %s: %w", path, err)
		}
		if change != nil {
			changes = append(changes, *change)
		}
	}

	return changes, nil
}

func (s *synchronizer) mergeSource(ctx context.Context, path, previous, next string) (*fileChange, error) {
	local, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(path)))
	localExists := !errors.Is(err, os.ErrNotExist)
	if err != nil && localExists {
		return nil, err
	}
	if !localExists && previous != "" {
		return nil, nil // preserve an intentional local deletion
	}

	var oldContent, newContent []byte
	if previous != "" {
		oldContent, err = s.repo.source(ctx, s.base, previous)
		if err != nil {
			return nil, err
		}
	}
	if next != "" {
		newContent, err = s.repo.source(ctx, s.revision, next)
		if err != nil {
			return nil, err
		}
	}

	switch {
	case next == "":
		if !bytes.Equal(local, oldContent) {
			return nil, errors.New("upstream removed a locally modified file; resolve manually")
		}
		return &fileChange{path: path}, nil
	case previous == "":
		if localExists && !bytes.Equal(local, newContent) {
			return nil, errors.New("new upstream file conflicts with an existing local file")
		}
	case localExists:
		newContent, err = mergeFile(ctx, s.work, local, oldContent, newContent)
		if err != nil {
			return nil, err
		}
	}
	if bytes.Equal(local, newContent) {
		return nil, nil
	}

	return &fileChange{
		path:    path,
		content: newContent,
	}, nil
}

func mergeFile(ctx context.Context, work string, local, base, next []byte) ([]byte, error) {
	paths := []string{
		filepath.Join(work, "ours.go"),
		filepath.Join(work, "base.go"),
		filepath.Join(work, "upstream.go"),
	}
	for index, content := range [][]byte{local, base, next} {
		if err := os.WriteFile(paths[index], content, 0o600); err != nil {
			return nil, err
		}
	}
	arguments := append([]string{"merge-file", "--stdout", "--diff3"}, paths...)
	output, err := exec.CommandContext(ctx, "git", arguments...).Output()
	if err != nil {
		return nil, fmt.Errorf("three-way merge failed; checkout was not changed: %w", err)
	}

	return output, nil
}

// applyChanges is not a filesystem transaction. Merges are already complete;
// if a filesystem write fails, the remaining diff must be resolved manually.
func applyChanges(root string, changes []fileChange) error {
	for _, change := range changes {
		if !filepath.IsLocal(change.path) {
			return fmt.Errorf("upstream path escapes the checkout: %q", change.path)
		}
		path := filepath.Join(root, filepath.FromSlash(change.path))
		if change.content == nil {
			if err := os.Remove(path); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, change.content, 0o644); err != nil {
			return err
		}
	}

	return nil
}
