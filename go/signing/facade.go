//
// facade.go
//
package signing

import (
    k4k3ruKMSSigningConfig "github.com/k4k3ru-hub/kms/go/signing/config"
    k4k3ruKMSSigningENV    "github.com/k4k3ru-hub/kms/go/signing/env"
    k4k3ruKMSSigningSpec   "github.com/k4k3ru-hub/kms/go/signing/spec"
)

type CreateKeyParams = k4k3ruKMSSigningSpec.CreateKeyParams
type CreateKeyResult = k4k3ruKMSSigningSpec.CreateKeyResult

type ENVConfig = k4k3ruKMSSigningConfig.ENVConfig

type SignParams = k4k3ruKMSSigningSpec.SignParams
type SignResult = k4k3ruKMSSigningSpec.SignResult

type VerifyParams = k4k3ruKMSSigningSpec.VerifyParams

type SignatureAlgorithm = k4k3ruKMSSigningSpec.SignatureAlgorithm

const (
    SignatureAlgorithmHMACSHA256      = k4k3ruKMSSigningSpec.SignatureAlgorithmHMACSHA256
    SignatureAlgorithmEd25519         = k4k3ruKMSSigningSpec.SignatureAlgorithmEd25519
    SignatureAlgorithmECDSAP256SHA256 = k4k3ruKMSSigningSpec.SignatureAlgorithmECDSAP256SHA256
)


//
// Create new signing env provider.
//
// Version:
//   - 2026-06-29: Added.
//
func NewENVProvider(config ENVConfig) (Provider, error) {
    return k4k3ruKMSSigningENV.NewProvider(config)
}
