//
// provider.go
//
package envaesgcm

import (
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "io"
    "os"
)

const (
    ProviderKind = "env-aes-gcm"
)

type Provider struct {
    keyVersion string
    aead       cipher.AEAD
}


//
// Create provider.
//
// Version:
//   - 2026-05-25: Added.
//
func NewProvider(config Config) (*Provider, error) {
    if err := config.Validate(); err != nil {
        return nil, fmt.Errorf("failed to create env aes gcm provider: %w", err)
    }

    encryptionKeyBase64 := os.Getenv(config.EnvName)
    if encryptionKeyBase64 == "" {
        return nil, fmt.Errorf("failed to create env aes gcm provider: missing required parameter: env_name=%q", config.EnvName)
    }

    encryptionKey, err := base64.StdEncoding.DecodeString(encryptionKeyBase64)
    if err != nil {
        return nil, fmt.Errorf("failed to create env aes gcm provider: invalid parameter: encryption_key_base64: %w", err)
    }

    switch len(encryptionKey) {
    case 16, 24, 32:
    default:
        return nil, fmt.Errorf("failed to create env aes gcm provider: invalid parameter: encryption_key_size=%d", len(encryptionKey))
    }

    block, err := aes.NewCipher(encryptionKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create env aes gcm provider: %w", err)
    }

    aead, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("failed to create env aes gcm provider: %w", err)
    }

    return &Provider{
        keyVersion: config.KeyVersion,
        aead:       aead,
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


