package releasefetch

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// cachePath returns the cache file for rawURL: the hex SHA-256 of the URL
// with a .data extension.
func (f *Fetcher) cachePath(rawURL string) string {
	sum := sha256.Sum256([]byte(rawURL))

	return filepath.Join(f.config.CacheDir, hex.EncodeToString(sum[:])+".data")
}

// readCache returns the cached body of rawURL and whether one was found.
func (f *Fetcher) readCache(rawURL string) ([]byte, bool, error) {
	if f.config.CacheDir == "" {
		return nil, false, nil
	}

	body, err := os.ReadFile(f.cachePath(rawURL))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, fmt.Errorf("read cached response: %w", err)
	}

	return body, true, nil
}

// writeCache stores body as the cached response of rawURL. It writes a
// temporary file and renames it, so a concurrent reader never sees a
// partial response.
//
// When two callers store the same URL at once, the first stored response
// wins. Windows refuses to replace a file that another reader holds open,
// and both responses are the same file.
func (f *Fetcher) writeCache(rawURL string, body []byte) error {
	if f.config.CacheDir == "" {
		return nil
	}

	if err := os.MkdirAll(f.config.CacheDir, 0o755); err != nil {
		return fmt.Errorf("create response cache: %w", err)
	}

	temporary, err := os.CreateTemp(f.config.CacheDir, "response-*.tmp")
	if err != nil {
		return fmt.Errorf("create cached response: %w", err)
	}

	if err := writeAndClose(temporary, body); err != nil {
		_ = os.Remove(temporary.Name())

		return err
	}

	return storeCached(temporary.Name(), f.cachePath(rawURL))
}

// storeCached renames the complete temporary file to destination. It
// discards the temporary file instead when another caller already stored
// destination.
func storeCached(temporary, destination string) error {
	err := os.Rename(temporary, destination)
	if err == nil {
		return nil
	}

	_ = os.Remove(temporary)

	if _, statErr := os.Stat(destination); statErr == nil {
		return nil
	}

	return fmt.Errorf("store cached response: %w", err)
}

// writeAndClose writes data to file, gives it ordinary read permissions, and
// closes it.
func writeAndClose(file *os.File, data []byte) error {
	if _, err := file.Write(data); err != nil {
		_ = file.Close()

		return fmt.Errorf("write cached response: %w", err)
	}

	if err := file.Chmod(0o644); err != nil {
		_ = file.Close()

		return fmt.Errorf("set permissions of cached response: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("close cached response: %w", err)
	}

	return nil
}
