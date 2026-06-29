//
// registry.go
//
package kms

import (
    "fmt"
)


type Registry struct {
    encryptionProviders map[string]EncryptionProvider
    signingProviders    map[string]SigningProvider

    defaultEncryptionProviderID string
    defaultSigningProviderID    string
}


//
// Create new registry.
//
// Version:
//   - 2026-06-29: Added.
//
func NewRegistry() *Registry {
    return &Registry{
        encryptionProviders: make(map[string]EncryptionProvider),
        signingProviders:    make(map[string]SigningProvider),
    }
}


//
// Register encryption provider.
//
// Version:
//   - 2026-06-29: Added.
//
func (r *Registry) RegisterEncryptionProvider(id string, provider EncryptionProvider) error {
    if r == nil {
        return fmt.Errorf("failed to register encryption provider: missing required parameter: registry=null")
    }
    if id == "" {
        return fmt.Errorf("failed to register encryption provider: missing required parameter: provider_id=%q", "empty")
    }
    if provider == nil {
        return fmt.Errorf("failed to register encryption provider: missing required parameter: provider=null")
    }
    if _, ok := r.encryptionProviders[id]; ok {
        return fmt.Errorf("failed to register encryption provider: already registered: provider_id=%q", id)
    }

    r.encryptionProviders[id] = provider

    return nil
}


//
// Register signing provider.
//
// Version:
//   - 2026-06-29: Added.
//
func (r *Registry) RegisterSigningProvider(id string, provider SigningProvider) error {
    if r == nil {
        return fmt.Errorf("failed to register signing provider: missing required parameter: registry=null")
    }
    if id == "" {
        return fmt.Errorf("failed to register signing provider: missing required parameter: provider_id=%q", "empty")
    }
    if provider == nil {
        return fmt.Errorf("failed to register signing provider: missing required parameter: provider=null")
    }
    if _, ok := r.signingProviders[id]; ok {
        return fmt.Errorf("failed to register signing provider: already registered: provider_id=%q", id)
    }

    r.signingProviders[id] = provider

    return nil
}


//
// Get encryption provider.
//
// Version:
//   - 2026-06-29: Added.
//
func (r *Registry) EncryptionProvider(id string) (EncryptionProvider, error) {
    if r == nil {
        return nil, fmt.Errorf("failed to get encryption provider: missing required parameter: registry=null")
    }
    if id == "" {
        return nil, fmt.Errorf("failed to get encryption provider: missing required parameter: provider_id=%q", "empty")
    }

    provider, ok := r.encryptionProviders[id]
    if !ok {
        return nil, fmt.Errorf("failed to get encryption provider: not found: provider_id=%q", id)
    }

    return provider, nil
}


//
// Get signing provider.
//
// Version:
//   - 2026-06-29: Added.
//
func (r *Registry) SigningProvider(id string) (SigningProvider, error) {
    if r == nil {
        return nil, fmt.Errorf("failed to get signing provider: missing required parameter: registry=null")
    }
    if id == "" {
        return nil, fmt.Errorf("failed to get signing provider: missing required parameter: provider_id=%q", "empty")
    }

    provider, ok := r.signingProviders[id]
    if !ok {
        return nil, fmt.Errorf("failed to get signing provider: not found: provider_id=%q", id)
    }

    return provider, nil
}


//
// Set default encryption provider.
//
// Version:
//   - 2026-06-29: Added.
//
func (r *Registry) SetDefaultEncryptionProvider(id string) error {
    if r == nil {
        return fmt.Errorf("failed to set default encryption provider: missing required parameter: registry=null")
    }
    if id == "" {
        return fmt.Errorf("failed to set default encryption provider: missing required parameter: provider_id=%q", "empty")
    }
    if _, ok := r.encryptionProviders[id]; !ok {
        return fmt.Errorf("failed to set default encryption provider: not found: provider_id=%q", id)
    }

    r.defaultEncryptionProviderID = id

    return nil
}

//
// Set default signing provider.
//
// Version:
//   - 2026-06-29: Added.
//
func (r *Registry) SetDefaultSigningProvider(id string) error {
    if r == nil {
        return fmt.Errorf("failed to set default signing provider: missing required parameter: registry=null")
    }
    if id == "" {
        return fmt.Errorf("failed to set default signing provider: missing required parameter: provider_id=%q", "empty")
    }
    if _, ok := r.signingProviders[id]; !ok {
        return fmt.Errorf("failed to set default signing provider: not found: provider_id=%q", id)
    }

    r.defaultSigningProviderID = id

    return nil
}

//
// Get default encryption provider ID.
//
// Version:
//   - 2026-06-29: Added.
//
func (r *Registry) DefaultEncryptionProviderID() (string, error) {
    if r == nil {
        return "", fmt.Errorf("failed to get default encryption provider id: missing required parameter: registry=null")
    }
    if r.defaultEncryptionProviderID == "" {
        return "", fmt.Errorf("failed to get default encryption provider id: missing required parameter: default_encryption_provider_id=%q", "empty")
    }

    return r.defaultEncryptionProviderID, nil
}

//
// Get default signing provider ID.
//
// Version:
//   - 2026-06-29: Added.
//
func (r *Registry) DefaultSigningProviderID() (string, error) {
    if r == nil {
        return "", fmt.Errorf("failed to get default signing provider id: missing required parameter: registry=null")
    }
    if r.defaultSigningProviderID == "" {
        return "", fmt.Errorf("failed to get default signing provider id: missing required parameter: default_signing_provider_id=%q", "empty")
    }

    return r.defaultSigningProviderID, nil
}
