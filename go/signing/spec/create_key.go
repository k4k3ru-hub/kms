//
// create_key.go
//
package spec

import (
    "fmt"
)


type CreateKeyParams struct {
    Algorithm  SignatureAlgorithm
    AAD        string
}

type CreateKeyResult struct {
    ProviderID string
    SecretRef  string
    Algorithm  SignatureAlgorithm
    PublicKey  *string
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
