// Command checksource checks formatting and vets production Go packages.
// It excludes test files and does not execute application code.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"
)

type packageSource struct {
	Dir            string
	GoFiles        []string
	CgoFiles       []string
	IgnoredGoFiles []string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	output, err := exec.CommandContext(ctx, "go", "list", "-json", "./...").Output()
	if err != nil {
		return commandError("list production packages", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var source packageSource
		if err := decoder.Decode(&source); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode package metadata: %w", err)
		}
		if err := checkPackage(ctx, source); err != nil {
			return fmt.Errorf("check %s: %w", source.Dir, err)
		}
	}
}

func checkPackage(ctx context.Context, source packageSource) error {
	files := append([]string(nil), source.GoFiles...)
	files = append(files, source.CgoFiles...)
	formatFiles := append([]string(nil), files...)
	for _, file := range source.IgnoredGoFiles {
		if !strings.HasSuffix(file, "_test.go") {
			formatFiles = append(formatFiles, file)
		}
	}
	if len(formatFiles) > 0 {
		command := exec.CommandContext(ctx, "gofmt", append([]string{"-l"}, formatFiles...)...)
		command.Dir = source.Dir
		output, err := command.Output()
		if err != nil {
			return commandError("check formatting", err)
		}
		if len(output) > 0 {
			return fmt.Errorf("files need gofmt:\n%s", output)
		}
	}
	if len(files) == 0 {
		return nil
	}

	command := exec.CommandContext(ctx, "go", append([]string{"vet"}, files...)...)
	command.Dir = source.Dir
	if _, err := command.Output(); err != nil {
		return commandError("vet production source", err)
	}

	return nil
}

func commandError(action string, err error) error {
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return fmt.Errorf("%s: %w\n%s", action, err, exit.Stderr)
	}

	return fmt.Errorf("%s: %w", action, err)
}
