//go:build linux

package analyze

func init() {
	// The resolver configuration Linux applies is resolv.conf, and the command
	// that writes it is resolvectl.
	Platform = "linux"
}
