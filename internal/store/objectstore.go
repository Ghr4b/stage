package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// ObjectStore defines the phase 0 interface for immutable artifact storage.
type ObjectStore interface {
	Put(ctx context.Context, key string, data []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
}

// LocalObjectStore implements ObjectStore for local disk (dev/test).
// In production, this would be an S3 or MinIO client.
type LocalObjectStore struct {
	baseDir string
}

func NewLocalObjectStore(baseDir string) (*LocalObjectStore, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create local object store dir: %w", err)
	}
	if err := os.Chmod(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to secure local object store dir: %w", err)
	}
	return &LocalObjectStore{baseDir: baseDir}, nil
}

func (s *LocalObjectStore) Put(ctx context.Context, key string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsLocal(key) {
		return fmt.Errorf("invalid object key")
	}
	fullPath := filepath.Join(s.baseDir, key)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(fullPath, data, 0600); err != nil {
		return err
	}
	return os.Chmod(fullPath, 0600)
}

func (s *LocalObjectStore) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsLocal(key) {
		return nil, fmt.Errorf("invalid object key")
	}
	fullPath := filepath.Join(s.baseDir, key)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("key not found: %s", key)
		}
		return nil, err
	}
	return data, nil
}
