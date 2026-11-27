package crypto

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// MasterKeySize is the required byte length for the AES-256 master key.
const MasterKeySize = 32

// LoadOrCreateMasterKey loads the 32-byte master key from path, or generates
// and atomically persists a new 0600 master key if the file does not exist.
// The boolean return value is true when a new key was generated.
func LoadOrCreateMasterKey(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != MasterKeySize {
			return nil, false, fmt.Errorf("invalid master key length at %s: got %d bytes, want %d", path, len(data), MasterKeySize)
		}
		if info, statErr := os.Stat(path); statErr == nil && info.Mode().Perm() != 0o600 {
			if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
				return nil, false, fmt.Errorf("enforce 0600 permissions on %s: %w", path, chmodErr)
			}
		}
		return data, false, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("read master key %s: %w", path, err)
	}

	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, false, fmt.Errorf("generate random master key: %w", err)
	}

	if err := WriteMasterKeyAtomic(path, key); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// WriteMasterKeyAtomic writes a 32-byte master key to path with 0600 permissions
// using a same-directory temp file, fsync, chmod, and atomic rename.
func WriteMasterKeyAtomic(path string, key []byte) error {
	if len(key) != MasterKeySize {
		return fmt.Errorf("invalid master key length: got %d bytes, want %d", len(key), MasterKeySize)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create master key directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".master.key.tmp-*")
	if err != nil {
		return fmt.Errorf("create temp master key file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp master key: %w", err)
	}
	if _, err := tmp.Write(key); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp master key: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp master key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp master key: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("chmod temp master key before rename: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp master key to %s: %w", path, err)
	}
	cleanup = false
	return nil
}

// ZeroBytes overwrites a byte slice with zeros.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
