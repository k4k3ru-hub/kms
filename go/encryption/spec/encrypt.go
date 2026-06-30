//
// encrypt.go
//
package spec

import (
    "fmt"
)


type EncryptParams struct {
    Plaintext []byte
    AAD       []byte
}


type EncryptResult struct {
    Ciphertext []byte
}


//
// Validate encrypt params.
//
// Version:
//   - 2026-06-29: Added.
//
func (p EncryptParams) Validate() error {
    if len(p.Plaintext) == 0 {
        return fmt.Errorf("missing required parameter: plain_text=%q", "empty")
    }
    if len(p.Plaintext) > 4096 {
        return fmt.Errorf("invalid parameter: plain_text=%q", "too long")
    }
    if len(p.AAD) > 1024 {
        return fmt.Errorf("invalid parameter: additional_authenticated_data=%q", "too long")
    }
    return nil
}
