// Package state stores the secrets that must survive between ctl runs.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/xrvo/hearthgate/internal/keys"
)

// State holds the WireGuard key material for both ends of the tunnel.
// It lives on the home server only.
type State struct {
	Version     int    `json:"version"`
	HomePrivate string `json:"home_private_key"`
	EdgePrivate string `json:"edge_private_key"`
	Preshared   string `json:"preshared_key"`
}

// New generates fresh key material.
func New() (*State, error) {
	home, err := keys.NewPrivate()
	if err != nil {
		return nil, err
	}
	edge, err := keys.NewPrivate()
	if err != nil {
		return nil, err
	}
	psk, err := keys.NewPreshared()
	if err != nil {
		return nil, err
	}
	return &State{Version: 1, HomePrivate: home, EdgePrivate: edge, Preshared: psk}, nil
}

// Exists reports whether a state file is present.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Load reads and sanity-checks a state file.
func Load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s not found: run `ctl init` first", path)
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", path, err)
	}
	for _, k := range []string{s.HomePrivate, s.EdgePrivate} {
		if _, err := keys.Public(k); err != nil {
			return nil, fmt.Errorf("%s is corrupt: %w", path, err)
		}
	}
	if s.Preshared == "" {
		return nil, fmt.Errorf("%s is corrupt: missing preshared key", path)
	}
	return &s, nil
}

// Save writes the state file readable by its owner only.
func (s *State) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
