//
// config.go
//
package envaesgcm

import (
    "fmt"
)

type Config struct {
    KeyBase64  string
    KeyVersion string
}


func (c Config) Validate() error {
    if c.KeyBase64 == "" {
        return fmt.Errorf("missing required parameter: key_base64=%q", "empty")
    }
    if c.KeyVersion == "" {
        return fmt.Errorf("missing required parameter: key_version=%q", "empty")
    }
    return nil
}
