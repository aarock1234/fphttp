package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const upstreamURL = "https://github.com/golang/go.git"

type upstream struct {
	directory string
}

func openUpstream(ctx context.Context, existing, work string) (*upstream, error) {
	if existing != "" {
		directory, err := filepath.Abs(existing)
		if err != nil {
			return nil, err
		}

		return &upstream{directory: directory}, nil
	}

	directory := filepath.Join(work, "go.git")
	repo := &upstream{directory: directory}
	command := exec.CommandContext(ctx, "git", "init", "--bare", directory)
	if output, err := command.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("initialize Go checkout: %w: %s", err, output)
	}
	for _, arguments := range [][]string{
		{"remote", "add", "origin", upstreamURL},
		{"config", "remote.origin.promisor", "true"},
		{"config", "remote.origin.partialclonefilter", "blob:none"},
	} {
		if _, err := repo.git(ctx, arguments...); err != nil {
			return nil, err
		}
	}

	return repo, nil
}

func (r *upstream) git(ctx context.Context, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "git", arguments...)
	command.Dir = r.directory
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", arguments[0], err, stderr.String())
	}

	return output, nil
}

func (r *upstream) resolve(ctx context.Context, ref string) (string, error) {
	if _, err := r.git(ctx, "fetch", "--depth=1", "--filter=blob:none", "origin", ref); err != nil {
		return "", err
	}
	output, err := r.git(ctx, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

func (r *upstream) files(ctx context.Context, revision string) (map[string]string, error) {
	output, err := r.git(ctx, "ls-tree", "-r", "--name-only", revision, "src/net/http", "src/internal/profile")
	if err != nil {
		return nil, err
	}

	files := make(map[string]string)
	for _, source := range strings.Fields(string(output)) {
		if !strings.HasSuffix(source, ".go") || strings.HasSuffix(source, "_test.go") || strings.Contains(source, "/testdata/") {
			continue
		}
		if source == "src/net/http/httptest/server.go" ||
			strings.HasPrefix(source, "src/net/http/internal/http3/") ||
			strings.HasPrefix(source, "src/net/http/internal/testcert/") {
			continue
		}
		local := strings.TrimPrefix(source, "src/net/http/")
		if strings.HasPrefix(source, "src/internal/profile/") {
			local = strings.TrimPrefix(source, "src/")
		}
		files[local] = source
	}

	return files, nil
}

func (r *upstream) source(ctx context.Context, revision, path string) ([]byte, error) {
	content, err := r.git(ctx, "show", revision+":"+path)
	if err != nil {
		return nil, err
	}

	return normalizeSource(path, content)
}

func validRevision(ref string) bool {
	if ref == "" || strings.HasPrefix(ref, "-") || strings.Contains(ref, "..") {
		return false
	}
	for _, character := range ref {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("/._-", character) {
			continue
		}

		return false
	}

	return true
}
