//go:build !darwin && !linux

package sysdns

// platformEncryptedProfiles has no reader on this platform, so an encrypted
// resolver is reported as none rather than guessed at.
func platformEncryptedProfiles(string) ([]string, error) { return nil, nil }
