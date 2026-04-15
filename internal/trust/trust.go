package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Store maps absolute file paths to their SHA-256 hashes.
type Store map[string]string

// TrustStorePath returns the path to the trust store file.
func TrustStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".config", "snip", "trusted.json")
}

// Load reads the trust store from disk. Returns an empty store if the file
// does not exist.
func Load() (Store, error) {
	data, err := os.ReadFile(TrustStorePath())
	if err != nil {
		if os.IsNotExist(err) {
			return make(Store), nil
		}
		return nil, fmt.Errorf("load trust store: %w", err)
	}
	var store Store
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("parse trust store: %w", err)
	}
	if store == nil {
		store = make(Store)
	}
	return store, nil
}

// LoadFrom reads a trust store from a specific path. Returns an empty store
// if the file does not exist.
func LoadFrom(path string) (Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(Store), nil
		}
		return nil, fmt.Errorf("load trust store: %w", err)
	}
	var store Store
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("parse trust store: %w", err)
	}
	if store == nil {
		store = make(Store)
	}
	return store, nil
}

// Save writes the trust store to disk, creating parent directories as needed.
func Save(store Store) error {
	return SaveTo(store, TrustStorePath())
}

// SaveTo writes the trust store to a specific path, creating parent
// directories as needed.
func SaveTo(store Store, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create trust store dir: %w", err)
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal trust store: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write trust store: %w", err)
	}
	return nil
}

// HashFile computes the SHA-256 hash of a file and returns it as a hex string.
func HashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("hash file %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// IsTrusted checks whether a file's current content matches the hash stored
// in the trust store.
func IsTrusted(store Store, path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	storedHash, ok := store[abs]
	if !ok {
		return false
	}
	currentHash, err := HashFile(abs)
	if err != nil {
		return false
	}
	return storedHash == currentHash
}

// Trust computes the SHA-256 hash of each path and adds it to the store.
// Paths are resolved to absolute before storing.
func Trust(store Store, paths []string) ([]TrustResult, error) {
	var results []TrustResult
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return results, fmt.Errorf("resolve path %s: %w", p, err)
		}
		hash, err := HashFile(abs)
		if err != nil {
			return results, err
		}
		store[abs] = hash
		results = append(results, TrustResult{Path: abs, Hash: hash})
	}
	return results, nil
}

// TrustResult holds the outcome of trusting a single file.
type TrustResult struct {
	Path string
	Hash string
}

// Untrust removes entries from the store. Paths are resolved to absolute.
// Returns the list of paths that were actually removed.
func Untrust(store Store, paths []string) ([]string, error) {
	var removed []string
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return removed, fmt.Errorf("resolve path %s: %w", p, err)
		}
		if _, ok := store[abs]; ok {
			delete(store, abs)
			removed = append(removed, abs)
		}
	}
	return removed, nil
}

// FindFilterFiles returns all .yaml and .yml files in a directory (non-recursive).
func FindFilterFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory %s: %w", dir, err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			files = append(files, filepath.Join(dir, name))
		}
	}
	return files, nil
}

// IsGlobalDir returns true if the directory is under the user's snip config
// directory (~/.config/snip/). Filters in global dirs are always trusted.
func IsGlobalDir(dir string) bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	globalPrefix := filepath.Join(home, ".config", "snip") + string(filepath.Separator)
	abs, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	abs += string(filepath.Separator)
	return strings.HasPrefix(abs, globalPrefix)
}
