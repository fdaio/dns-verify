package sysdns

import "fmt"

// EncryptedProfiles lists the encrypted resolver settings installed here.
//
// macOS keeps them in per-domain profiles and Linux in the resolver daemon's own
// configuration, so the platform decides which file is read.
func EncryptedProfiles(dir string) ([]string, error) {
	profiles, err := platformEncryptedProfiles(dir)
	if err != nil {
		return nil, fmt.Errorf("read encrypted resolver settings: %w", err)
	}
	return profiles, nil
}
