package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// replaceFile writes data to a temporary file beside path and renames it over
// path, so readers see either the previous content or the complete new
// content, never a partial write. It does not sync data to stable storage.
func replaceFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}

	if err := writeAndClose(file, data); err != nil {
		_ = os.Remove(file.Name())

		return err
	}

	if err := os.Rename(file.Name(), path); err != nil {
		_ = os.Remove(file.Name())

		return fmt.Errorf("replace %s: %w", path, err)
	}

	return nil
}

// writeAndClose writes data to file, gives it ordinary read permissions, and
// closes it.
func writeAndClose(file *os.File, data []byte) error {
	if _, err := file.Write(data); err != nil {
		_ = file.Close()

		return fmt.Errorf("write %s: %w", file.Name(), err)
	}

	if err := file.Chmod(0o644); err != nil {
		_ = file.Close()

		return fmt.Errorf("set permissions of %s: %w", file.Name(), err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", file.Name(), err)
	}

	return nil
}
