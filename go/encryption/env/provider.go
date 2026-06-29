//
// provider.go
//
package env

import (
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "io"

    k4k3ruKMSEncryptionConfig "github.com/k4k3ru-hub/kms/go/encryption/config"
    k4k3ruKMSEncryptionSpec   "github.com/k4k3ru-hub/kms/go/encryption/spec"
)


type Provider struct {
    id   string
    aead cipher.AEAD
}


//
// Create new env provider.
//
// Version:
//   - 2026-06-29: Added.
//
func NewProvider(config k4k3ruKMSEncryptionConfig.ENVConfig) (*Provider, error) {
    // Validate config.
    if err := config.Validate(); err != nil {
        return nil, fmt.Errorf("failed to create new encryption env provider: %w", err)
    }

    // Validate encryption key.
    encryptionKey, err := base64.StdEncoding.DecodeString(config.EncryptionKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create new encryption env provider: invalid parameter: encryption_key: %w", err)
    }

    switch len(encryptionKey) {
    case 16, 24, 32:
    default:
        return nil, fmt.Errorf("failed to create new encryption env provider: invalid parameter: encryption_key_size=%d", len(encryptionKey))
    }

    block, err := aes.NewCipher(encryptionKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create new encryption env provider: %w", err)
    }

    aead, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("failed to create new encryption env provider: %w", err)
    }

    return &Provider{
        id:   config.ID,
        aead: aead,
    }, nil
}


//
// Get ID.
//
// Version:
//   - 2026-06-29: Added.
//
func (p *Provider) ID() string {
    // Guard.
    if p == nil {
        return ""
    }

    return p.id
}


//
// Encrypt plain text.
//
// Version:
//   - 2026-06-29: Added.
//
func (p *Provider) Encrypt(ctx context.Context, params k4k3ruKMSEncryptionSpec.EncryptParams) (*k4k3ruKMSEncryptionSpec.EncryptResult, error) {
    if p == nil {
        return nil, fmt.Errorf("failed to encrypt: missing required parameter: provider=null")
    }
    if p.aead == nil {
        return nil, fmt.Errorf("failed to encrypt: missing required parameter: aead=null")
    }
    if err := params.Validate(); err != nil {
        return nil, fmt.Errorf("failed to encrypt: %w", err)
    }
    if ctx == nil {
        ctx = context.Background()
    }
    if err := ctx.Err(); err != nil {
        return nil, fmt.Errorf("failed to encrypt: %w", err)
    }

    nonce := make([]byte, p.aead.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, fmt.Errorf("failed to encrypt: %w", err)
    }

    sealed := p.aead.Seal(nil, nonce, []byte(params.PlainText), []byte(params.AAD))

    payload := make([]byte, 0, len(nonce)+len(sealed))
    payload = append(payload, nonce...)
    payload = append(payload, sealed...)

    return &k4k3ruKMSEncryptionSpec.EncryptResult{
        CipherText: base64.StdEncoding.EncodeToString(payload),
    }, nil
}


//
// Decrypt cipher text.
//
// Version:
//   - 2026-06-29: Added.
//
func (p *Provider) Decrypt(ctx context.Context, params k4k3ruKMSEncryptionSpec.DecryptParams) (*k4k3ruKMSEncryptionSpec.DecryptResult, error) {
    if p == nil {
        return nil, fmt.Errorf("failed to decrypt: missing required parameter: provider=null")
    }
    if p.aead == nil {
        return nil, fmt.Errorf("failed to decrypt: missing required parameter: aead=null")
    }
    if err := params.Validate(); err != nil {
        return nil, fmt.Errorf("failed to decrypt: %w", err)
    }
    if ctx == nil {
        ctx = context.Background()
    }
    if err := ctx.Err(); err != nil {
        return nil, fmt.Errorf("failed to decrypt: %w", err)
    }

    payload, err := base64.StdEncoding.DecodeString(params.CipherText)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt: invalid parameter: cipher_text: %w", err)
    }

    nonceSize := p.aead.NonceSize()
    if len(payload) <= nonceSize {
        return nil, fmt.Errorf("failed to decrypt: invalid parameter: cipher_text_size=%d", len(payload))
    }

    nonce := payload[:nonceSize]
    sealed := payload[nonceSize:]

    plainTextBytes, err := p.aead.Open(nil, nonce, sealed, []byte(params.AAD))
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt: %w", err)
    }

    return &k4k3ruKMSEncryptionSpec.DecryptResult{
        PlainText: string(plainTextBytes),
    }, nil
}
