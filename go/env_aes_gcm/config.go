//
// config.go
//
package envaesgcm

import (
    "fmt"
)

type Config struct {
    KeyVersion string
    EnvName    string
}


func (c Config) Validate() error {
    if c.KeyVersion == "" {
        return fmt.Errorf("missing required parameter: key_version=%q", "empty")
    }
    if c.EnvName == "" {
        return fmt.Errorf("missing required parameter: env_name=%q", "empty")
    }
    return nil
}
