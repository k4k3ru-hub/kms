//
// provider.go
//
package env

import (
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/ed25519"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "io"

    "github.com/k4k3ru-hub/kms/go/config"
)

const (
    ProviderKind = "env"
)

type Provider struct {
    keyVersion       string
    aead             cipher.AEAD
    macKey           []byte
    signingAlgorithm config.SigningAlgorithm
    signingKey       []byte
}


//
// Create new env provider.
//
// Version:
//   - 2026-06-25: Added.
//
func NewProvider(c config.Config) (*Provider, error) {
    // Validate config.
    if err := c.Validate(); err != nil {
        return nil, fmt.Errorf("failed to create env provider: %w", err)
    }

    encryptionKey, err := base64.StdEncoding.DecodeString(c.EncryptionKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create new env provider: invalid parameter: encryption_key: %w", err)
    }

    switch len(encryptionKey) {
    case 16, 24, 32:
    default:
        return nil, fmt.Errorf("failed to create new env provider: invalid parameter: encryption_key_size=%d", len(encryptionKey))
    }

    macKey, err := base64.StdEncoding.DecodeString(c.MACKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create env provider: invalid parameter: mac_key: %w", err)
    }
    if len(macKey) == 0 {
        return nil, fmt.Errorf("failed to create env provider: invalid parameter: mac_key=%q", "empty")
    }

    signingKey, err := base64.StdEncoding.DecodeString(c.SigningKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create env provider: invalid parameter: signing_key: %w", err)
    }

    switch c.SigningAlgorithm {
    case config.SigningAlgorithmEd25519:
        if len(signingKey) != ed25519.PrivateKeySize {
            return nil, fmt.Errorf("failed to create env provider: invalid parameter: signing_key_size=%d", len(signingKey))
        }
    default:
        return nil, fmt.Errorf("failed to create env provider: invalid parameter: signing_algorithm=%q", c.SigningAlgorithm)
    }

    block, err := aes.NewCipher(encryptionKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create new env provider: %w", err)
    }

    aead, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("failed to create new env provider: %w", err)
    }

    return &Provider{
        keyVersion:       c.KeyVersion,
        aead:             aead,
        macKey:           macKey,
        signingAlgorithm: c.SigningAlgorithm,
        signingKey:       signingKey,
    }, nil
}


//
// Get provider kind.
//
// Version:
//   - 2026-05-25: Added.
//
func (p *Provider) ProviderKind() string {
    return ProviderKind
}

//
// Get key version.
//
// Version:
//   - 2026-05-25: Added.
//
func (p *Provider) KeyVersion() string {
    if p == nil {
        return ""
    }
    return p.keyVersion
}


//
// Encrypt secret.
//
// Version:
//   - 2026-05-25: Added.
//
func (p *Provider) Encrypt(ctx context.Context, plainText string) (string, error) {
    if p == nil {
        return "", fmt.Errorf("failed to encrypt secret: missing required parameter: provider=null")
    }
    if p.aead == nil {
        return "", fmt.Errorf("failed to encrypt secret: missing required parameter: aead=null")
    }
    if plainText == "" {
        return "", fmt.Errorf("failed to encrypt secret: missing required parameter: plain_text=%q", "empty")
    }
    if ctx == nil {
        ctx = context.Background()
    }
    if err := ctx.Err(); err != nil {
        return "", fmt.Errorf("failed to encrypt secret: %w", err)
    }

    nonce := make([]byte, p.aead.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", fmt.Errorf("failed to encrypt secret: %w", err)
    }

    sealed := p.aead.Seal(nil, nonce, []byte(plainText), nil)

    payload := make([]byte, 0, len(nonce)+len(sealed))
    payload = append(payload, nonce...)
    payload = append(payload, sealed...)

    return base64.StdEncoding.EncodeToString(payload), nil
}


//
// Decrypt secret.
//
// Version:
//   - 2026-05-25: Added.
//
func (p *Provider) Decrypt(ctx context.Context, cipherText string) (string, error) {
    if p == nil {
        return "", fmt.Errorf("failed to decrypt secret: missing required parameter: provider=null")
    }
    if p.aead == nil {
        return "", fmt.Errorf("failed to decrypt secret: missing required parameter: aead=null")
    }
    if cipherText == "" {
        return "", fmt.Errorf("failed to decrypt secret: missing required parameter: cipher_text=%q", "empty")
    }
    if ctx == nil {
        ctx = context.Background()
    }
    if err := ctx.Err(); err != nil {
        return "", fmt.Errorf("failed to decrypt secret: %w", err)
    }

    payload, err := base64.StdEncoding.DecodeString(cipherText)
    if err != nil {
        return "", fmt.Errorf("failed to decrypt secret: invalid parameter: cipher_text: %w", err)
    }

    nonceSize := p.aead.NonceSize()
    if len(payload) <= nonceSize {
        return "", fmt.Errorf("failed to decrypt secret: invalid parameter: cipher_text_size=%d", len(payload))
    }

    nonce := payload[:nonceSize]
    sealed := payload[nonceSize:]

    plainTextBytes, err := p.aead.Open(nil, nonce, sealed, nil)
    if err != nil {
        return "", fmt.Errorf("failed to decrypt secret: %w", err)
    }

    return string(plainTextBytes), nil
}


//
// Sign payload by HMAC-SHA256.
//
// Version:
//   - 2026-06-25: Added.
//
func (p *Provider) SignHMACSHA256(ctx context.Context, payload []byte) (string, error) {
    if p == nil {
        return "", fmt.Errorf("failed to sign hmac sha256: missing required parameter: provider=null")
    }
    if len(p.macKey) == 0 {
        return "", fmt.Errorf("failed to sign hmac sha256: missing required parameter: mac_key=%q", "empty")
    }
    if len(payload) == 0 {
        return "", fmt.Errorf("failed to sign hmac sha256: missing required parameter: payload=%q", "empty")
    }
    if ctx == nil {
        ctx = context.Background()
    }
    if err := ctx.Err(); err != nil {
        return "", fmt.Errorf("failed to sign hmac sha256: %w", err)
    }

    mac := hmac.New(sha256.New, p.macKey)

    if _, err := mac.Write(payload); err != nil {
        return "", fmt.Errorf("failed to sign hmac sha256: %w", err)
    }

    return hex.EncodeToString(mac.Sum(nil)), nil
}


//
// Verify HMAC-SHA256 signature.
//
// Version:
//   - 2026-06-25: Added.
//
func (p *Provider) VerifyHMACSHA256(ctx context.Context, payload []byte, signature string) error {
    if p == nil {
        return fmt.Errorf("failed to verify hmac sha256: missing required parameter: provider=null")
    }
    if len(p.macKey) == 0 {
        return fmt.Errorf("failed to verify hmac sha256: missing required parameter: mac_key=%q", "empty")
    }
    if len(payload) == 0 {
        return fmt.Errorf("failed to verify hmac sha256: missing required parameter: payload=%q", "empty")
    }
    if signature == "" {
        return fmt.Errorf("failed to verify hmac sha256: missing required parameter: signature=%q", "empty")
    }
    if ctx == nil {
        ctx = context.Background()
    }
    if err := ctx.Err(); err != nil {
        return fmt.Errorf("failed to verify hmac sha256: %w", err)
    }

    signatureBytes, err := hex.DecodeString(signature)
    if err != nil {
        return fmt.Errorf("failed to verify hmac sha256: invalid parameter: signature: %w", err)
    }

    mac := hmac.New(sha256.New, p.macKey)
    if _, err := mac.Write(payload); err != nil {
        return fmt.Errorf("failed to verify hmac sha256: %w", err)
    }

    expectedSignatureBytes := mac.Sum(nil)

    if !hmac.Equal(signatureBytes, expectedSignatureBytes) {
        return fmt.Errorf("failed to verify hmac sha256: signature_mismatch")
    }

    return nil
}
