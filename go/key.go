//
// key.go
//
package kms

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/base64"
    "fmt"
)

const (
    encryptionKeySize = 32
    macKeySize        = 32
)


//
// Generate encryption key base64.
//
// Version:
//   - 2026-06-25: Added.
//
func GenerateEncryptionKeyBase64() (string, error) {
    key := make([]byte, encryptionKeySize)

    if _, err := rand.Read(key); err != nil {
        return "", fmt.Errorf("failed to generate encryption key base64: %w", err)
    }

    return base64.StdEncoding.EncodeToString(key), nil
}


//
// Generate MAC key base64.
//
// Version:
//   - 2026-06-25: Added.
//
func GenerateMACKeyBase64() (string, error) {
    key := make([]byte, macKeySize)

    if _, err := rand.Read(key); err != nil {
        return "", fmt.Errorf("failed to generate mac key base64: %w", err)
    }

    return base64.StdEncoding.EncodeToString(key), nil
}


//
// Generate Ed25519 private key base64.
//
// Version:
//   - 2026-06-25: Added.
//
func GenerateEd25519PrivateKeyBase64() (string, error) {
    _, privateKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return "", fmt.Errorf("failed to generate ed25519 private key base64: %w", err)
    }

    return base64.StdEncoding.EncodeToString(privateKey), nil
}

