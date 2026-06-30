//
// sign.go
//
package spec

import (
    "fmt"    
)


//
// Parameter:
//   - AAD: env provider only
//
type SignParams struct {
    SecretRef []byte
    AAD       []byte
}

type SignResult struct {
    Signature []byte
    Algorithm SignatureAlgorithm
}


//
// Validate sign params.
//
// Version:
//   - 2026-06-29: Added.
//
func (p SignParams) Validate() error {
    if len(p.SecretRef) == 0 {
        return fmt.Errorf("missing required parameter: secret_ref=%q", "empty")
    }
    if len(p.SecretRef) > 4096 {
        return fmt.Errorf("invalid parameter: secret_ref=%q", "too long")
    }
    if len(p.AAD) > 1024 {
        return fmt.Errorf("invalid parameter: additional_authenticated_data=%q", "too long")
    }
    return nil
}
