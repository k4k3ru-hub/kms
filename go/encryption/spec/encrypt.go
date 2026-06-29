//
// encrypt.go
//
package spec

import (
    "fmt"
)


type EncryptParams struct {
    PlainText string
    AAD       string
}


type EncryptResult struct {
    CipherText string
}


//
// Validate encrypt params.
//
// Version:
//   - 2026-06-29: Added.
//
func (p EncryptParams) Validate() error {
    if p.PlainText == "" {
        return fmt.Errorf("missing required parameter: plain_text=%q", "empty")
    }
    if len(p.PlainText) > 4096 {
        return fmt.Errorf("invalid parameter: plain_text=%q", "too long")
    }
    if len(p.AAD) > 1024 {
        return fmt.Errorf("invalid parameter: additional_authenticated_data=%q", "too long")
    }
    return nil
}
