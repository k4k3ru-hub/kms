//
// config.go
//
package config

import (
    "fmt"
)


type Config struct {
    KeyVersion       string
    EncryptionKey    string
    MACKey           string
    SigningAlgorithm SigningAlgorithm
    SigningKey       string
}


//
// Validate config.
//
// Version:
//   - 2026-06-25: Added.
//
func (c Config) Validate() error {
    if c.KeyVersion == "" {
        return fmt.Errorf("missing required parameter: key_version=%q", "empty")
    }
    if c.MACKey == "" {
        return fmt.Errorf("missing required parameter: mac_key=%q", "empty")
    }
    if c.EncryptionKey == "" {
        return fmt.Errorf("missing required parameter: encryption_key=%q", "empty")
    }
    if err := c.SigningAlgorithm.Validate(); err != nil {
        return err
    }
    if c.SigningKey == "" {
        return fmt.Errorf("missing required parameter: signing_key=%q", "empty")
    }
    return nil
}
