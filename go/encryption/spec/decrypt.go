//
// decrypt.go
//
package spec

import (
    "fmt"
)

type DecryptParams struct {
    CipherText string
    AAD        string
}

type DecryptResult struct {
    PlainText string
}


//
// Validate decrypt params.
//
// Version:
//   - 2026-06-29: Added.
//
func (p DecryptParams) Validate() error {
    if p.CipherText == "" {
        return fmt.Errorf("missing required parameter: cipher_text=%q", "empty")
    }
    if len(p.CipherText) > 4096 {
        return fmt.Errorf("invalid parameter: cipher_text=%q", "too long")
    }
    if len(p.AAD) > 1024 {
        return fmt.Errorf("invalid parameter: additional_authenticated_data=%q", "too long")
    }
    return nil
}
