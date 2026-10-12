package sysdns

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ResolverDir holds the per-domain resolver profiles that macOS installs for
// split DNS and for encrypted resolvers.
const ResolverDir = "/etc/resolver"

// EncryptedProfile is a resolver profile that specifies an encrypted transport.
type EncryptedProfile struct {
	// Domain is the domain the profile applies to.
	Domain string
	// Port is the configured port.
	Port uint16
	// URL is the DoH template, when the profile uses one.
	URL string
}

// Scheme renders the transport as DoH, DoT, or the plain port.
func (p EncryptedProfile) Scheme() string {
	switch {
	case p.URL != "":
		return "DoH"
	case p.Port == 853:
		return "DoT"
	default:
		return "port " + strconv.Itoa(int(p.Port))
	}
}

// ReadEncryptedProfiles reports the profiles in dir that specify DoH or DoT.
// A missing directory is not an error: it only means no profile is installed.
func ReadEncryptedProfiles(dir string) ([]EncryptedProfile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	var out []EncryptedProfile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		profile, ok := parseProfile(strings.TrimSuffix(entry.Name(), ".conf"), readFile(dir, entry.Name()))
		if ok {
			out = append(out, profile)
		}
	}
	return out, nil
}

func readFile(dir, name string) string {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return string(data)
}

// parseProfile reads the resolver.conf keys that decide the transport.
//
// The file format is one "key value" pair per line, so it cannot share the
// parser that reads the colon-separated output of scutil.
func parseProfile(domain, content string) (EncryptedProfile, bool) {
	profile := EncryptedProfile{Domain: domain}
	for line := range strings.SplitSeq(content, "\n") {
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		key, value, found := strings.Cut(strings.TrimSpace(line), " ")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "port":
			if port, err := strconv.ParseUint(value, 10, 16); err == nil {
				profile.Port = uint16(port)
			}
		case "url-template", "url":
			profile.URL = value
		}
	}
	if profile.URL != "" || profile.Port == 853 || profile.Port == 443 {
		return profile, true
	}
	return EncryptedProfile{}, false
}
