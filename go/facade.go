//
// facade.go
//
package kms

import (
    k4k3ruKMSConfig     "github.com/k4k3ru-hub/kms/go/config"
    k4k3ruKMSEncryption "github.com/k4k3ru-hub/kms/go/encryption"
    k4k3ruKMSSigning    "github.com/k4k3ru-hub/kms/go/signing"
)

const (
    ProviderKindAWS = k4k3ruKMSConfig.ProviderKindAWS
    ProviderKindENV = k4k3ruKMSConfig.ProviderKindENV
    ProviderKindGCP = k4k3ruKMSConfig.ProviderKindGCP
)

type EncryptionProvider = k4k3ruKMSEncryption.Provider
type SigningProvider = k4k3ruKMSSigning.Provider

type EncryptionENVConfig = k4k3ruKMSEncryption.ENVConfig
type SigningENVConfig = k4k3ruKMSSigning.ENVConfig

type CreateKeyParams = k4k3ruKMSSigning.CreateKeyParams
type SignParams = k4k3ruKMSSigning.SignParams
type VerifyParams = k4k3ruKMSSigning.VerifyParams

type ENVConfig = k4k3ruKMSConfig.ENVConfig
type ENVConfigOption = k4k3ruKMSConfig.ENVConfigOption

type SigningSignatureAlgorithm = k4k3ruKMSSigning.SignatureAlgorithm

const (
    SigningSignatureAlgorithmHMACSHA256      = k4k3ruKMSSigning.SignatureAlgorithmHMACSHA256
    SigningSignatureAlgorithmEd25519         = k4k3ruKMSSigning.SignatureAlgorithmEd25519
    SigningSignatureAlgorithmECDSAP256SHA256 = k4k3ruKMSSigning.SignatureAlgorithmECDSAP256SHA256
)


//
// Load config from env file.
//
// Version:
//   - 2026-06-30: Added.
//
func LoadConfigFromEnv(config *ENVConfigOption) (*k4k3ruKMSConfig.ENVConfig, error) {
    return k4k3ruKMSConfig.LoadFromEnv(config)
}


//
// Create new encryption env provider.
//
// Version:
//   - 2026-06-29: Added.
//
func NewEncryptionENVProvider(config EncryptionENVConfig) (EncryptionProvider, error) {
    return k4k3ruKMSEncryption.NewENVProvider(config)
}


//
// Create new signing env provider.
//
// Version:
//   - 2026-06-29: Added.
//
func NewSigningENVProvider(config SigningENVConfig) (SigningProvider, error) {
    return k4k3ruKMSSigning.NewENVProvider(config)
}
