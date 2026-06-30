//
// create_key.go
//
package spec

import (
    "fmt"
)


type CreateKeyParams struct {
    Algorithm  SignatureAlgorithm
    AAD        []byte
}

type CreateKeyResult struct {
    ProviderID string
    SecretRef  []byte
    Algorithm  SignatureAlgorithm
    PublicKey  []byte
    SecretRaw  []byte
}


//
// Validate create key params.
//
// Version:
//   - 2026-06-29: Added.
//
func (p CreateKeyParams) Validate() error {
    if err := p.Algorithm.Validate(); err != nil {
        return err
    }
    if len(p.AAD) > 1024 {
        return fmt.Errorf("invalid parameter: additional_authenticated_data=%q", "too long")
    }
    return nil
}
