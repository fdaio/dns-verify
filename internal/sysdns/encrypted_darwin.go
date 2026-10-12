//go:build darwin

package sysdns

// platformEncryptedProfiles reads the per-domain resolver profiles, which is
// where macOS keeps an encrypted resolver.
func platformEncryptedProfiles(dir string) ([]string, error) {
	profiles, err := ReadEncryptedProfiles(dir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, p.Domain+" "+p.Scheme())
	}
	return out, nil
}
