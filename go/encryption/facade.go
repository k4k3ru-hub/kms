//
// facade.go
//
package encryption

import (
    k4k3ruKMSEncryptionConfig "github.com/k4k3ru-hub/kms/go/encryption/config"
    k4k3ruKMSEncryptionENV    "github.com/k4k3ru-hub/kms/go/encryption/env"
    k4k3ruKMSEncryptionSpec   "github.com/k4k3ru-hub/kms/go/encryption/spec"
)

type DecryptParams = k4k3ruKMSEncryptionSpec.DecryptParams
type DecryptResult = k4k3ruKMSEncryptionSpec.DecryptResult

type ENVConfig = k4k3ruKMSEncryptionConfig.ENVConfig

type EncryptParams = k4k3ruKMSEncryptionSpec.EncryptParams
type EncryptResult = k4k3ruKMSEncryptionSpec.EncryptResult



//
// Create new encryption env provider.
//
// Version:
//   - 2026-06-29: Added.
//
func NewENVProvider(config ENVConfig) (Provider, error) {
    return k4k3ruKMSEncryptionENV.NewProvider(config)
}
