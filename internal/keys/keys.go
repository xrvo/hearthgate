// Package keys generates WireGuard key material using only the standard library.
package keys

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// NewPrivate returns a new base64-encoded Curve25519 private key.
func NewPrivate() (string, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), nil
}

// Public derives the base64-encoded public key for a private key.
func Public(private string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(private)
	if err != nil {
		return "", fmt.Errorf("private key is not valid base64: %w", err)
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// NewPreshared returns a new base64-encoded 32-byte preshared key.
func NewPreshared() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
