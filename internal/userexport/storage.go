package userexport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Storage is the persistence target for finished bundles. Production
// deployments back this with object storage; local dev and tests use
// LocalDiskStorage. The interface is intentionally small so an object-storage
// adapter can be added later without touching API/worker code.
type Storage interface {
	// Put writes the bundle from r at the given key.
	Put(ctx context.Context, key string, r io.Reader) (string, error)
	// Open returns a read handle for a bundle previously written via Put.
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	// Delete removes the bundle. Missing keys must not error so the worker
	// can re-run after a crash without spurious failures.
	Delete(ctx context.Context, key string) error
}

// LocalDiskStorage persists bundles under a base directory. Files are
// chmod 0600 so the bundle is not world-readable on shared dev hosts; the
// directory is created with chmod 0700 for the same reason.
type LocalDiskStorage struct {
	BaseDir string
}

// NewLocalDiskStorage returns a storage backend rooted at baseDir, creating
// the directory if needed.
func NewLocalDiskStorage(baseDir string) (*LocalDiskStorage, error) {
	clean := strings.TrimSpace(baseDir)
	if clean == "" {
		return nil, errors.New("userexport: base dir is required")
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return nil, fmt.Errorf("create export dir: %w", err)
	}
	return &LocalDiskStorage{BaseDir: clean}, nil
}

// Put writes a bundle from r to baseDir/key and returns the absolute path.
func (s *LocalDiskStorage) Put(_ context.Context, key string, r io.Reader) (path string, err error) {
	path, err = s.resolve(key)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create export subdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("open export file: %w", err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close export file: %w", closeErr)
		}
	}()
	if _, err := io.Copy(f, r); err != nil {
		return "", fmt.Errorf("write export file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("sync export file: %w", err)
	}
	return path, nil
}

// Open returns a read handle for an existing bundle.
func (s *LocalDiskStorage) Open(_ context.Context, key string) (io.ReadCloser, error) {
	path, err := s.resolve(key)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

// Delete removes a bundle. Missing files are not an error.
func (s *LocalDiskStorage) Delete(_ context.Context, key string) error {
	path, err := s.resolve(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete export file: %w", err)
	}
	return nil
}

// resolve joins key onto baseDir while rejecting traversal attempts. The key
// is constructed server-side from a UUID, but defending here keeps a future
// API change from accidentally introducing a path-traversal bug.
func (s *LocalDiskStorage) resolve(key string) (string, error) {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return "", errors.New("userexport: key is required")
	}
	if strings.Contains(trimmed, "..") || strings.HasPrefix(trimmed, "/") || strings.Contains(trimmed, "\x00") {
		return "", fmt.Errorf("userexport: invalid key %q", key)
	}
	cleaned := filepath.Clean(trimmed)
	full := filepath.Join(s.BaseDir, cleaned)
	rel, err := filepath.Rel(s.BaseDir, full)
	if err != nil {
		return "", fmt.Errorf("userexport: invalid key %q: %w", key, err)
	}
	if strings.HasPrefix(rel, "..") || rel == ".." {
		return "", fmt.Errorf("userexport: key escapes base dir: %q", key)
	}
	return full, nil
}
