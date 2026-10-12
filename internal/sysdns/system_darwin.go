package sysdns

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// System reads the live DNS configuration.
func System(ctx context.Context) (Config, error) {
	out, err := run(ctx, "scutil", "--dns")
	if err != nil {
		return Config{}, err
	}
	return Parse(out)
}

// ExplicitServers reports the DNS servers set on each enabled network service.
// A service with no entry inherits whatever the network hands out, which is the
// difference between a chosen resolver and an imposed one.
func ExplicitServers(ctx context.Context) (map[string][]string, error) {
	out, err := run(ctx, "networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}

	result := make(map[string][]string)
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		// A leading asterisk marks a disabled service.
		if strings.HasPrefix(line, "*") {
			continue
		}
		name := strings.TrimPrefix(line, "*")
		value, err := run(ctx, "networksetup", "-getdnsservers", name)
		if err != nil {
			continue
		}
		result[name] = serversFromNetworksetup(value)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("networksetup -listallnetworkservices: %w", err)
	}
	return result, nil
}

// serversFromNetworksetup drops the sentence networksetup prints when a
// service has no configured server.
func serversFromNetworksetup(out string) []string {
	var servers []string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		entry := strings.TrimSpace(sc.Text())
		if entry == "" || strings.HasPrefix(entry, "There aren't any DNS Servers") {
			continue
		}
		servers = append(servers, entry)
	}
	return servers
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err == nil {
		return string(out), nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && stderr.Len() > 0 {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "),
			err, strings.TrimSpace(stderr.String()))
	}
	return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
}
