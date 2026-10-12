//go:build linux

package sysdns

import "github.com/fdaio/dns-verify/internal/sysdns/resolvconf"

// platformEncryptedProfiles reads the systemd-resolved configuration, because
// Linux has no per-domain resolver directory for this setting.
func platformEncryptedProfiles(dir string) ([]string, error) {
	return resolvconf.EncryptedProfiles(resolvedConfigDir)
}

// resolvedConfigDir holds the systemd-resolved configuration.
const resolvedConfigDir = "/etc/systemd/resolved.conf.d"
