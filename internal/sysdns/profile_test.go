package sysdns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadEncryptedProfiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "cloudflare.com.conf", "nameserver 1.1.1.1\nport 443\nurl-template https://cloudflare-dns.com/dns-query\n")
	write(t, dir, "quad9.conf", "nameserver 9.9.9.9\nport 853\n")
	write(t, dir, "plain.conf", "nameserver 192.168.1.1\nport 53\n")
	write(t, dir, "notes.txt", "not a profile\n")

	profiles, err := ReadEncryptedProfiles(dir)
	if err != nil {
		t.Fatalf("ReadEncryptedProfiles: %v", err)
	}
	if len(profiles) != 2 {
		t.Fatalf("got %d profiles, want 2: %+v", len(profiles), profiles)
	}
	if profiles[0].Domain != "cloudflare.com" || profiles[0].Scheme() != "DoH" {
		t.Errorf("first profile = %+v, want the cloudflare.com DoH profile", profiles[0])
	}
	if profiles[1].Domain != "quad9" || profiles[1].Scheme() != "DoT" {
		t.Errorf("second profile = %+v, want the quad9 DoT profile", profiles[1])
	}
}

func TestReadEncryptedProfilesMissingDir(t *testing.T) {
	profiles, err := ReadEncryptedProfiles(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatalf("a missing directory is not a failure: %v", err)
	}
	if len(profiles) != 0 {
		t.Errorf("got %d profiles, want none", len(profiles))
	}
}

func TestParseProfileRejectsPlainResolver(t *testing.T) {
	if _, ok := parseProfile("plain", "nameserver 192.168.1.1\nport 53\n"); ok {
		t.Error("a cleartext profile must not be reported as encrypted")
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
