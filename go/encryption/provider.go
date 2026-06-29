//
// provider.go
//
package encryption

import (
    "context"

     k4k3ruKMSEncryptionSpec "github.com/k4k3ru-hub/kms/go/encryption/spec"
)


type Provider interface {
    ID() string
    Encrypt(ctx context.Context, params k4k3ruKMSEncryptionSpec.EncryptParams) (*k4k3ruKMSEncryptionSpec.EncryptResult, error) 
    Decrypt(ctx context.Context, params k4k3ruKMSEncryptionSpec.DecryptParams) (*k4k3ruKMSEncryptionSpec.DecryptResult, error)
}



