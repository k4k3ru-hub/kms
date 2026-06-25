//
// config_alias.go
//
package kms

import (
    "github.com/k4k3ru-hub/kms/go/config"
)


type Config = config.Config
type SigningAlgorithm = config.SigningAlgorithm

const (
    SigningAlgorithmEd25519         = config.SigningAlgorithmEd25519
    SigningAlgorithmECDSAP256SHA256 = config.SigningAlgorithmECDSAP256SHA256
)
