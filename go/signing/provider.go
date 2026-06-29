//
// provider.go
//
package signing

import (
    "context"

    k4k3ruKMSSigningSpec "github.com/k4k3ru-hub/kms/go/signing/spec"    
)


type Provider interface {
    ID() string
    CreateKey(ctx context.Context, params k4k3ruKMSSigningSpec.CreateKeyParams) (*k4k3ruKMSSigningSpec.CreateKeyResult, error)
    Sign(ctx context.Context, params k4k3ruKMSSigningSpec.SignParams, payload []byte) (*k4k3ruKMSSigningSpec.SignResult, error)
    Verify(ctx context.Context, params k4k3ruKMSSigningSpec.VerifyParams, payload []byte, signature []byte) error
}
