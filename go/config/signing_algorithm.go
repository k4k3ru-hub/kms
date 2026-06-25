//
// signing_algorithm.go
//
package config

import (
    "fmt"
)


type SigningAlgorithm string

const (
    SigningAlgorithmEd25519         SigningAlgorithm = "ed25519"
    SigningAlgorithmECDSAP256SHA256 SigningAlgorithm = "ecdsa-p256-sha256"
)


func (a SigningAlgorithm) Validate() error {
    if a == "" {
        return fmt.Errorf("missing required parameter: signing_algorithm=%q", "empty")
    }
    if len(a) > 32 {
        return fmt.Errorf("invalid parameter: signing_algorithm=%q", "too long")
    }
    switch a {
    case SigningAlgorithmEd25519,
         SigningAlgorithmECDSAP256SHA256:
        return nil
    default:
        return fmt.Errorf("invalid parameter: signing_algorithm=%q", string(a))
    }
}


func (a SigningAlgorithm) GCPKMSAlgorithm() string {
    switch a {
    case SigningAlgorithmECDSAP256SHA256:
        return "EC_SIGN_P256_SHA256"
    default:
        return ""
    }
}
