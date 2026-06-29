//
// verify.go
//
package spec

import (
    "fmt"
)


//
// Parameter:
//   - AAD: env provider only
//
type VerifyParams struct {
    SecretRef string
    PublicKey *string
    AAD       string
}


//
// Validate verify params.
//
// Version:
//   - 2026-06-29: Added.
//
func (p VerifyParams) Validate() error {
    if p.SecretRef == "" {
        return fmt.Errorf("missing required parameter: secret_ref=%q", "empty")
    }
    if len(p.SecretRef) > 4096 {
        return fmt.Errorf("invalid parameter: secret_ref=%q", "too long")
    }
    if len(p.AAD) > 1024 {
        return fmt.Errorf("invalid parameter: aad=%q", "too long")
    }
    if p.PublicKey != nil {
        if *p.PublicKey == "" {
            return fmt.Errorf("invalid parameter: public_key=%q", "empty")
        }
        if len(*p.PublicKey) > 4096 {
            return fmt.Errorf("invalid parameter: public_key=%q", "too long")
        }
    }

    return nil
}
