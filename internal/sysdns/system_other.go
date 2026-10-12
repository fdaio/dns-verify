//go:build !darwin && !linux

package sysdns

import (
	"context"
	"fmt"
	"runtime"
)

// System reports that the live configuration cannot be read. The merged
// SystemConfiguration state the parser expects exists on macOS only.
func System(context.Context) (Config, error) {
	return Config{}, fmt.Errorf("reading the DNS configuration needs macOS, not %s", runtime.GOOS)
}

// ExplicitServers reports the same limitation, so a caller cannot mistake an
// unreadable configuration for an empty one.
func ExplicitServers(context.Context) ([]Service, error) {
	return nil, fmt.Errorf("reading the DNS configuration needs macOS, not %s", runtime.GOOS)
}
