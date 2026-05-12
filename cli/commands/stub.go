package commands

import "fmt"

// handleStub returns a consistent not-implemented error.
//
// CLI callers should treat this as a feature-gap signal rather than a runtime
// failure in cryptographic operations.
func handleStub(name string) error {
	return fmt.Errorf("command %q is not implemented yet", name)
}
