//
// provider.go
//
package kms

import (
    "context"
    "fmt"

    "github.com/k4k3ru-hub/kms/go/config"
    "github.com/k4k3ru-hub/kms/go/env"
)


type Provider interface {
    ProviderKind() string
    KeyVersion() string
    Encrypt(ctx context.Context, plainText string) (string, error)
    Decrypt(ctx context.Context, cipherText string) (string, error)
    SignHMACSHA256(ctx context.Context, payload []byte) (string, error)
    VerifyHMACSHA256(ctx context.Context, payload []byte, signature string) error
}

type ProviderKind string

const (
    ProviderKindENV ProviderKind = env.ProviderKind
    ProviderKindGCP ProviderKind = "gcp"
    ProviderKindAWS ProviderKind = "aws"
)


//
// Create new env provider.
//
// Version:
//   - 2026-06-25: Added.
//
func NewEnvProvider(c Config) (Provider, error) {
    return env.NewProvider(config.Config(c))
}


//
// Check whether provider kind is valid.
//
// Version:
//   - 2026-06-25: Added.
//
func (k ProviderKind) IsValid() bool {
    switch k {
    case ProviderKindENV, ProviderKindGCP, ProviderKindAWS:
        return true
    default:
        return false
    }
}


//
// Validate provider kind.
//
// Version:
//   - 2026-06-25: Added.
//
func (k ProviderKind) Validate() error {
    s := string(k)
    if len(s) > 16 {
        return fmt.Errorf("invalid parameter: provider_kind=%q", "too long")
    }
    if !k.IsValid() {
        return fmt.Errorf("invalid parameter: provider_kind=%q", s)
    }
    return nil
}
