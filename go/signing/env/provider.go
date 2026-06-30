//
// provider.go
//
package env

import (
    "context"
    "crypto/ed25519"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/json"
    "fmt"

    k4k3ruKMSSigningConfig "github.com/k4k3ru-hub/kms/go/signing/config"
    k4k3ruKMSSigningSpec   "github.com/k4k3ru-hub/kms/go/signing/spec"
    k4k3ruKMSEncryption    "github.com/k4k3ru-hub/kms/go/encryption"
)


type Provider struct {
    id                 string
    encryptionProvider k4k3ruKMSEncryption.Provider
}

type envSecretRef struct {
    ID         string
    Algorithm  string
    Ciphertext []byte
}


//
// Create new env provider.
//
// Version:
//   - 2026-06-29: Added.
//
func NewProvider(config k4k3ruKMSSigningConfig.ENVConfig) (*Provider, error) {
    // Validate config.
    if err := config.Validate(); err != nil {
        return nil, fmt.Errorf("failed to create new signing env provider: %w", err)
    }

    // Create new encryption env provider.
    encryptionENVConfig := k4k3ruKMSEncryption.ENVConfig{
        ID:  config.ID + ":encryption",
        Key: config.SecretEncryptionKey,
    }
    encryptionProvider, err := k4k3ruKMSEncryption.NewENVProvider(encryptionENVConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create new signing env provider: %w", err)
    }

    return &Provider{
        id:                 config.ID,
        encryptionProvider: encryptionProvider,
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
// Create key.
//
// Version:
//   - 2026-06-29: Added.
//
func (p *Provider) CreateKey(ctx context.Context, params k4k3ruKMSSigningSpec.CreateKeyParams) (*k4k3ruKMSSigningSpec.CreateKeyResult, error) {
    // Guard.
    if p == nil {
        return nil, fmt.Errorf("failed to create key: missing required parameter: provider=null")
    }
    if p.encryptionProvider == nil {
        return nil, fmt.Errorf("failed to create key: missing required parameter: encryption_provider=null")
    }
    if err := params.Validate(); err != nil {
        return nil, fmt.Errorf("failed to create key: %w", err)
    }
    if ctx == nil {
        ctx = context.Background()
    }
    if err := ctx.Err(); err != nil {
        return nil, fmt.Errorf("failed to create key: %w", err)
    }

    result := &k4k3ruKMSSigningSpec.CreateKeyResult{
        ProviderID: p.id,
        Algorithm:  params.Algorithm,
    }

    var secretRaw []byte

    switch params.Algorithm {
    case k4k3ruKMSSigningSpec.SignatureAlgorithmHMACSHA256:
        secretKey := make([]byte, k4k3ruKMSSigningSpec.MACKeySize)
        if _, err := rand.Read(secretKey); err != nil {
            return nil, fmt.Errorf("failed to create key: %w", err)
        }
        result.SecretRaw = secretKey
    case k4k3ruKMSSigningSpec.SignatureAlgorithmEd25519:
        publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
        if err != nil {
            return nil, fmt.Errorf("failed to create key: %w", err)
        }

        result.SecretRaw = privateKey
        result.PublicKey = publicKey
    default:
        return nil, fmt.Errorf("failed to create key: invalid parameter: signature_algorithm=%q", string(params.Algorithm))
    }

    // Encrypt secret raw.
    aad := params.AAD
    if len(aad) == 0 {
        aad = []byte(p.id)
    }

    encryptParams := k4k3ruKMSEncryption.EncryptParams{
        Plaintext: secretRaw,
        AAD:       aad,
    }

    encryptedResult, err := p.encryptionProvider.Encrypt(ctx, encryptParams)
    if err != nil {
        return nil, fmt.Errorf("failed to create key: %w", err)
    }
    if encryptedResult == nil {
        return nil, fmt.Errorf("failed to create key: unexpected error: encrypted_result=null")
    }

    // Build secret  ref
    ref := envSecretRef{
        ID:         p.id,
        Algorithm:  string(params.Algorithm),
        Ciphertext: encryptedResult.Ciphertext,
    }

    secretRef, err := json.Marshal(ref)
    if err != nil {
        return nil, fmt.Errorf("failed to create key: %w", err)
    }

    result.SecretRef = secretRef

    return result, nil
}


//
// Sign payload.
//
// Version:
//   - 2026-06-29: Added.
//
func (p *Provider) Sign(ctx context.Context, params k4k3ruKMSSigningSpec.SignParams, payload []byte) (*k4k3ruKMSSigningSpec.SignResult, error) {
    // Guard.
    if p == nil {
        return nil, fmt.Errorf("failed to sign: missing required parameter: provider=null")
    }
    if p.encryptionProvider == nil {
        return nil, fmt.Errorf("failed to sign: missing required parameter: encryption_provider=null")
    }
    if err := params.Validate(); err != nil {
        return nil, fmt.Errorf("failed to sign: %w", err)
    }
    if len(payload) == 0 {
        return nil, fmt.Errorf("failed to sign: missing required parameter: payload=%q", "empty")
    }
    if ctx == nil {
        ctx = context.Background()
    }
    if err := ctx.Err(); err != nil {
        return nil, fmt.Errorf("failed to sign: %w", err)
    }

    // Decode secret ref.
    var ref envSecretRef
    if err := json.Unmarshal(params.SecretRef, &ref); err != nil {
        return nil, fmt.Errorf("failed to sign: %w", err)
    }
    if ref.ID != p.id {
        return nil, fmt.Errorf("failed to sign: invalid parameter: provider_id=%q", ref.ID)
    }

    // Decrypt secret raw.
    aad := params.AAD
    if len(aad) == 0 {
        aad = []byte(p.id)
    }

    decryptParams := k4k3ruKMSEncryption.DecryptParams{
        Ciphertext: ref.Ciphertext,
        AAD:        aad,
    }

    decryptedResult, err := p.encryptionProvider.Decrypt(ctx, decryptParams)
    if err != nil {
        return nil, fmt.Errorf("failed to sign: %w", err)
    }
    if decryptedResult == nil {
        return nil, fmt.Errorf("failed to sign: unexpected error: decrypted_result=null")
    }

    secretRaw := decryptedResult.Plaintext

    var signature []byte

    algorithm := k4k3ruKMSSigningSpec.SignatureAlgorithm(ref.Algorithm)
    switch algorithm {
    case k4k3ruKMSSigningSpec.SignatureAlgorithmHMACSHA256:
        if len(secretRaw) != k4k3ruKMSSigningSpec.MACKeySize {
            return nil, fmt.Errorf("failed to sign: invalid parameter: mac_key_size=%d", len(secretRaw))
        }

        mac := hmac.New(sha256.New, secretRaw)
        if _, err := mac.Write(payload); err != nil {
            return nil, fmt.Errorf("failed to sign: %w", err)
        }

        signature = mac.Sum(nil)
    case k4k3ruKMSSigningSpec.SignatureAlgorithmEd25519:
        if len(secretRaw) != ed25519.PrivateKeySize {
            return nil, fmt.Errorf("failed to sign: invalid parameter: ed25519_private_key_size=%d", len(secretRaw))
        }

        signature = ed25519.Sign(ed25519.PrivateKey(secretRaw), payload)
    default:
        return nil, fmt.Errorf("failed to sign: invalid parameter: signature_algorithm=%q", string(ref.Algorithm))
    }

    return &k4k3ruKMSSigningSpec.SignResult{
        Signature: signature,
        Algorithm: algorithm,
    }, nil
}


//
// Verify signature.
//
// Version:
//   - 2026-06-29: Added.
//
func (p *Provider) Verify(ctx context.Context, params k4k3ruKMSSigningSpec.VerifyParams, payload []byte, signature []byte) error {
    // Guard.
    if p == nil {
        return fmt.Errorf("failed to verify: missing required parameter: provider=null")
    }
    if p.encryptionProvider == nil {
        return fmt.Errorf("failed to verify: missing required parameter: encryption_provider=null")
    }
    if err := params.Validate(); err != nil {
        return fmt.Errorf("failed to verify: %w", err)
    }
    if len(payload) == 0 {
        return fmt.Errorf("failed to verify: missing required parameter: payload=%q", "empty")
    }
    if len(signature) == 0 {
        return fmt.Errorf("failed to verify: missing required parameter: signature=%q", "empty")
    }
    if ctx == nil {
        ctx = context.Background()
    }
    if err := ctx.Err(); err != nil {
        return fmt.Errorf("failed to verify: %w", err)
    }

    // Decode secret ref.
    var ref envSecretRef
    if err := json.Unmarshal(params.SecretRef, &ref); err != nil {
        return fmt.Errorf("failed to verify: %w", err)
    }
    if ref.ID != p.id {
        return fmt.Errorf("failed to verify: invalid parameter: provider_id=%q", ref.ID)
    }

    algorithm := k4k3ruKMSSigningSpec.SignatureAlgorithm(ref.Algorithm)
    switch algorithm {
    case k4k3ruKMSSigningSpec.SignatureAlgorithmHMACSHA256:
        // HMAC verify needs secret key.
        aad := params.AAD
        if len(aad) == 0 {
            aad = []byte(p.id)
        }

        decryptParams := k4k3ruKMSEncryption.DecryptParams{
            Ciphertext: ref.Ciphertext,
            AAD:        aad,
        }

        decryptedResult, err := p.encryptionProvider.Decrypt(ctx, decryptParams)
        if err != nil {
            return fmt.Errorf("failed to verify: %w", err)
        }
        if decryptedResult == nil {
            return fmt.Errorf("failed to verify: unexpected error: decrypted_result=null")
        }

        secretRaw := decryptedResult.Plaintext

        if len(secretRaw) != k4k3ruKMSSigningSpec.MACKeySize {
            return fmt.Errorf("failed to verify: invalid parameter: mac_key_size=%d", len(secretRaw))
        }

        mac := hmac.New(sha256.New, secretRaw)
        if _, err := mac.Write(payload); err != nil {
            return fmt.Errorf("failed to verify: %w", err)
        }

        expectedSignature := mac.Sum(nil)
        if !hmac.Equal(signature, expectedSignature) {
            return fmt.Errorf("failed to verify: invalid signature")
        }

        return nil

    case k4k3ruKMSSigningSpec.SignatureAlgorithmEd25519:
        if len(params.PublicKey) == 0 {
            return fmt.Errorf("failed to verify: missing required parameter: public_key=%q", "empty")
        }

        if len(params.PublicKey) != ed25519.PublicKeySize {
            return fmt.Errorf("failed to verify: invalid parameter: ed25519_public_key_size=%d", len(params.PublicKey))
        }

        if !ed25519.Verify(ed25519.PublicKey(params.PublicKey), payload, signature) {
            return fmt.Errorf("failed to verify: invalid signature")
        }

        return nil

    default:
        return fmt.Errorf("failed to verify: invalid parameter: signature_algorithm=%q", string(ref.Algorithm))
    }
}


