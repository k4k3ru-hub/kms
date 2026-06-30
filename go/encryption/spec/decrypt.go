//
// decrypt.go
//
package spec

import (
    "fmt"
)

type DecryptParams struct {
    Ciphertext []byte
    AAD        []byte
}

type DecryptResult struct {
    Plaintext []byte
}


//
// Validate decrypt params.
//
// Version:
//   - 2026-06-29: Added.
//
func (p DecryptParams) Validate() error {
    if len(p.Ciphertext) == 0 {
        return fmt.Errorf("missing required parameter: cipher_text=%q", "empty")
    }
    if len(p.Ciphertext) > 4096 {
        return fmt.Errorf("invalid parameter: cipher_text=%q", "too long")
    }
    if len(p.AAD) > 1024 {
        return fmt.Errorf("invalid parameter: additional_authenticated_data=%q", "too long")
    }
    return nil
}
