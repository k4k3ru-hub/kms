//
// env.go
//
package env

import (
    "fmt"
)


type ENVConfig struct {
    ID            string
    EncryptionKey string
}


//
// Validate env config.
//
// Version:
//   - 2026-06-29: Added.
//
func (c ENVConfig) Validate() error {
    if c.ID == "" {
        return fmt.Errorf("missing required parameter: id=%q", "empty")
    }
    if c.EncryptionKey == "" {
        return fmt.Errorf("missing required parameter: encryption_key=%q", "empty")
    }
    if len(c.EncryptionKey) > 4096 {
        return fmt.Errorf("invalid parameter: encryption_key=%q", "too long")
    }
    return nil
}
