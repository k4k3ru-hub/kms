//
// env.go
//
package env

import (
    "fmt"
)


type ENVConfig struct {
    ID  string
    Key string
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
    if c.Key == "" {
        return fmt.Errorf("missing required parameter: key=%q", "empty")
    }
    if len(c.Key) > 4096 {
        return fmt.Errorf("invalid parameter: key=%q", "too long")
    }
    return nil
}
