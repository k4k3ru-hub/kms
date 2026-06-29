//
// signature_algorithm.go
//
package spec

import (
    "fmt"
)


type SignatureAlgorithm string

const (
    SignatureAlgorithmHMACSHA256      SignatureAlgorithm = "hmac-sha256"
    SignatureAlgorithmEd25519         SignatureAlgorithm = "ed25519"
    SignatureAlgorithmECDSAP256SHA256 SignatureAlgorithm = "ecdsa-p256-sha256"
)


func (a SignatureAlgorithm) Validate() error {
    if a == "" {
        return fmt.Errorf("missing required parameter: signature_algorithm=%q", "empty")
    }
    if len(a) > 32 {
        return fmt.Errorf("invalid parameter: signature_algorithm=%q", "too long")
    }
    switch a {
    case SignatureAlgorithmHMACSHA256,
         SignatureAlgorithmEd25519,
         SignatureAlgorithmECDSAP256SHA256:
        return nil
    default:
        return fmt.Errorf("invalid parameter: signature_algorithm=%q", string(a))
    }
}


func (a SignatureAlgorithm) GCPKMSAlgorithm() string {
    switch a {
    case SignatureAlgorithmECDSAP256SHA256:
        return "EC_SIGN_P256_SHA256"
    default:
        return ""
    }
}
