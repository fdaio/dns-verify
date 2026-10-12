package resolvconf

import "os/exec"

// execCommand is a variable so a test can supply output without a Linux host.
var execCommand = func(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
