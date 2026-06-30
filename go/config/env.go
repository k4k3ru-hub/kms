//
// env.go
//
package config

import (
    "fmt"
    "os"
    "strings"
)

const (
    envKMSDefaultEncryptionProviderID  = "KMS_DEFAULT_ENCRYPTION_PROVIDER_ID"
    envKMSDefaultSigningProviderID     = "KMS_DEFAULT_SIGNING_PROVIDER_ID"
    envKMSEncryptionProviderConfigKeys = "KMS_ENCRYPTION_PROVIDER_CONFIG_KEYS"
    envKMSSigningProviderConfigKeys    = "KMS_SIGNING_PROVIDER_CONFIG_KEYS"

    ProviderKindAWS = "aws"
    ProviderKindENV = "env"
    ProviderKindGCP = "gcp"
)


type ENVConfig struct {
    DefaultEncryptionProviderID string
    DefaultSigningProviderID    string
    EncryptionProviders         []ENVEncryptionProviderConfig
    SigningProviders            []ENVSigningProviderConfig
}

type ENVConfigOption struct {
    ENVNamePrefix string
}

type ENVEncryptionProviderConfig struct {
    ConfigKey         string
    Kind              string
    ProviderID        string
    Key               string
    envNameKind       string
    envNameProviderID string
    envNameKey        string
}

type ENVSigningProviderConfig struct {
    ConfigKey                  string
    Kind                       string
    ProviderID                 string
    SecretEncryptionKey        string
    envNameKind                string
    envNameProviderID          string
    envNameSecretEncryptionKey string
}


//
// Load from env file.
//
// Version:
//   - 2026-06-30: Added.
//
func LoadFromEnv(option *ENVConfigOption) (*ENVConfig, error) {
    // 
    envNamePrefix := ""
    if option != nil {
        envNamePrefix = option.ENVNamePrefix
    }

    envConfig := &ENVConfig{
        DefaultEncryptionProviderID: os.Getenv(fmt.Sprintf("%s_%s", envNamePrefix, envKMSDefaultEncryptionProviderID)),
        DefaultSigningProviderID:    os.Getenv(fmt.Sprintf("%s_%s", envNamePrefix, envKMSDefaultSigningProviderID)),
    }

    encryptionProviderConfigKeys := strings.Split(os.Getenv(fmt.Sprintf("%s_%s", envNamePrefix, envKMSEncryptionProviderConfigKeys)), ",")
    for _, configKey := range encryptionProviderConfigKeys {
        configKey = strings.ToUpper(strings.TrimSpace(configKey))
        if configKey == "" {
            continue
        }

        envNameKind       := fmt.Sprintf("%s_KMS_ENCRYPTION_%s_%s", envNamePrefix, configKey, "KIND")
        envNameProviderID := fmt.Sprintf("%s_KMS_ENCRYPTION_%s_%s", envNamePrefix, configKey, "PROVIDER_ID")
        envNameKey        := fmt.Sprintf("%s_KMS_ENCRYPTION_%s_%s", envNamePrefix, configKey, "KEY")

        providerConfig := ENVEncryptionProviderConfig{
            ConfigKey:         configKey,
            Kind:              os.Getenv(envNameKind),
            ProviderID:        os.Getenv(envNameProviderID),
            Key:               os.Getenv(envNameKey),
            envNameKind:       envNameKind,
            envNameProviderID: envNameProviderID,
            envNameKey:        envNameKey,
        }

        envConfig.EncryptionProviders = append(envConfig.EncryptionProviders, providerConfig)
    }

    signingProviderConfigKeys := strings.Split(os.Getenv(fmt.Sprintf("%s_%s", envNamePrefix, envKMSSigningProviderConfigKeys)), ",")
    for _, configKey := range signingProviderConfigKeys {
        configKey = strings.ToUpper(strings.TrimSpace(configKey))
        if configKey == "" {
            continue
        }

        envNameKind                := fmt.Sprintf("%s_KMS_SIGNING_%s_%s", envNamePrefix, configKey, "KIND")
        envNameProviderID          := fmt.Sprintf("%s_KMS_SIGNING_%s_%s", envNamePrefix, configKey, "PROVIDER_ID")
        envNameSecretEncryptionKey := fmt.Sprintf("%s_KMS_SIGNING_%s_%s", envNamePrefix, configKey, "SECRET_ENCRYPTION_KEY")

        providerConfig := ENVSigningProviderConfig{
            ConfigKey:                  configKey,
            Kind:                       os.Getenv(envNameKind),
            ProviderID:                 os.Getenv(envNameProviderID),
            SecretEncryptionKey:        os.Getenv(envNameSecretEncryptionKey),
            envNameKind:                envNameKind,
            envNameProviderID:          envNameProviderID,
            envNameSecretEncryptionKey: envNameSecretEncryptionKey,
        }

        envConfig.SigningProviders = append(envConfig.SigningProviders, providerConfig)
    }

    // Validate config.
    if err := envConfig.Validate(); err != nil {
        return nil, fmt.Errorf("failed to load kms config from env: %w", err)
    }

    return envConfig, nil
}


//
// Validate ENV config.
//
// Version:
//   - 2026-06-30: Added.
//
func (c *ENVConfig) Validate() error {
    if c == nil {
        return fmt.Errorf("missing required parameter: env_config=null")
    }
    if c.DefaultEncryptionProviderID == "" && len(c.EncryptionProviders) > 0 {
        return fmt.Errorf("missing required parameter: %s=%q", envKMSDefaultEncryptionProviderID, "empty")
    }
    if c.DefaultEncryptionProviderID != "" && len(c.EncryptionProviders) == 0 {
        return fmt.Errorf("missing required parameter: %s=%q", envKMSEncryptionProviderConfigKeys, "empty")
    }
    if c.DefaultSigningProviderID == "" && len(c.SigningProviders) > 0 {
        return fmt.Errorf("missing required parameter: %s=%q", envKMSDefaultSigningProviderID, "empty")
    }
    if c.DefaultSigningProviderID != ""&& len(c.SigningProviders) == 0 {
        return fmt.Errorf("missing required parameter: %s=%q", envKMSSigningProviderConfigKeys, "empty")
    }

    encryptionProviderIDs := make(map[string]struct{})
    for _, providerConfig := range c.EncryptionProviders {
        if err := providerConfig.Validate(); err != nil {
            return err
        }
        if _, ok := encryptionProviderIDs[providerConfig.ProviderID]; ok {
            return fmt.Errorf("invalid parameter: duplicate encryption provider: provider_id=%q", providerConfig.ProviderID)
        }
        encryptionProviderIDs[providerConfig.ProviderID] = struct{}{}
    }

    signingProviderIDs := make(map[string]struct{})
    for _, providerConfig := range c.SigningProviders {
        if err := providerConfig.Validate(); err != nil {
            return err
        }
        if _, ok := signingProviderIDs[providerConfig.ProviderID]; ok {
            return fmt.Errorf("invalid parameter: duplicate signing provider: provider_id=%q", providerConfig.ProviderID)
        }
        signingProviderIDs[providerConfig.ProviderID] = struct{}{}
    }

    if _, ok := encryptionProviderIDs[c.DefaultEncryptionProviderID]; !ok {
        return fmt.Errorf("not found: default_encryption_provider_id=%q", c.DefaultEncryptionProviderID)
    }

    if _, ok := signingProviderIDs[c.DefaultSigningProviderID]; !ok {
        return fmt.Errorf("not found: default_signing_provider_id=%q", c.DefaultSigningProviderID)
    }

    return nil
}


//
// Validate ENV encryption provider config.
//
// Version:
//   - 2026-06-30: Added.
//
func (c ENVEncryptionProviderConfig) Validate() error {
    if c.ConfigKey == "" {
        return fmt.Errorf("missing required parameter: encryption_provider_config_key=%q", "empty")
    }
    if c.Kind == "" {
        return fmt.Errorf("missing required parameter: %s=%q", c.envNameKind, "empty")
    }
    if c.ProviderID == "" {
        return fmt.Errorf("missing required parameter: %s=%q", c.envNameProviderID, "empty")
    }

    switch c.Kind {
    case ProviderKindENV:
        if c.Key == "" {
            return fmt.Errorf("missing required parameter: %s=%q", c.envNameKey, "empty")
        }
// Note: Not supported yet.
//    case ProviderKindGCP:
//    case ProviderKindAWS:
    default:
        return fmt.Errorf("unsupported encryption provider: kind=%q", c.Kind)
    }

    return nil
}


//
// Validate ENV signing provider config.
//
// Version:
//   - 2026-06-30: Added.
//
func (c ENVSigningProviderConfig) Validate() error {
    if c.ConfigKey == "" {
        return fmt.Errorf("missing required parameter: signing_provider_config_key=%q", "empty")
    }
    if c.Kind == "" {
        return fmt.Errorf("missing required parameter: %s=%q", c.envNameKind, "empty")
    }
    if c.ProviderID == "" {
        return fmt.Errorf("missing required parameter: %s=%q", c.envNameProviderID, "empty")
    }

    switch c.Kind {
    case ProviderKindENV:
        if c.SecretEncryptionKey == "" {
            return fmt.Errorf("missing required parameter: %s=%q", c.envNameSecretEncryptionKey, "empty")
        }
// Note: Not supported yet.
//    case ProviderKindGCP:
//    case ProviderKindAWS:
    default:
        return fmt.Errorf("unsupported signing provider: kind=%q", c.Kind)
    }

    return nil
}
