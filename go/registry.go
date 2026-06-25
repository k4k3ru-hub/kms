//
// registry.go
//
package kms

import (
    "fmt"
)

type Registry struct {
    providers       map[string]Provider
    defaultProvider Provider
}


func NewRegistry(defaultProvider Provider, providers ...Provider) (*Registry, error) {
    if defaultProvider == nil {
        return nil, fmt.Errorf("failed to create secret provider registry: missing required parameter: default_provider=null")
    }

    r := &Registry{
        providers:       make(map[string]Provider),
        defaultProvider: defaultProvider,
    }

    if err := r.register(defaultProvider); err != nil {
        return nil, err
    }

    for _, provider := range providers {
        if err := r.register(provider); err != nil {
            return nil, err
        }
    }

    return r, nil
}

func (r *Registry) Default() Provider {
    if r == nil {
        return nil
    }
    return r.defaultProvider
}

func (r *Registry) Get(providerKind string, keyVersion string) (Provider, error) {
    if r == nil {
        return nil, fmt.Errorf("failed to get secret provider: missing required parameter: registry=null")
    }
    if providerKind == "" {
        return nil, fmt.Errorf("failed to get secret provider: missing required parameter: provider_kind=%q", "empty")
    }
    if keyVersion == "" {
        return nil, fmt.Errorf("failed to get secret provider: missing required parameter: key_version=%q", "empty")
    }

    provider, ok := r.providers[registryKey(providerKind, keyVersion)]
    if !ok {
        return nil, fmt.Errorf("failed to get secret provider: unsupported provider_kind=%q key_version=%q", providerKind, keyVersion)
    }

    return provider, nil
}

func (r *Registry) register(provider Provider) error {
    if r == nil {
        return fmt.Errorf("failed to register secret provider: missing required parameter: registry=null")
    }
    if provider == nil {
        return fmt.Errorf("failed to register secret provider: missing required parameter: provider=null")
    }

    providerKind := provider.ProviderKind()
    if providerKind == "" {
        return fmt.Errorf("failed to register secret provider: missing required parameter: provider_kind=%q", "empty")
    }

    keyVersion := provider.KeyVersion()
    if keyVersion == "" {
        return fmt.Errorf("failed to register secret provider: missing required parameter: key_version=%q", "empty")
    }

    key := registryKey(providerKind, keyVersion)
    if _, exists := r.providers[key]; exists {
        return fmt.Errorf("failed to register secret provider: duplicate provider_kind=%q key_version=%q", providerKind, keyVersion)
    }

    r.providers[key] = provider

    return nil
}

func registryKey(providerKind string, keyVersion string) string {
    return providerKind + ":" + keyVersion
}
