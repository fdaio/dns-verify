//go:build darwin

package analyze

// The resolver configuration macOS applies is SystemConfiguration, and the
// command that writes it is networksetup.
func init() {
	Platform = "macos"
}
