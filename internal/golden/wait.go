package golden

import (
	"crypto/tls"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// waitForPort blocks until addr accepts a connection, or the
// container dies, or the deadline passes.
//
// Polling the port is not enough on its own: if slapd exits on
// a configuration error the port never opens and a plain
// timeout hides the reason. So the container is checked too,
// and its logs come back in the error.
func waitForPort(addr, container string) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if handshakes(addr) {
			return nil
		}
		if !running(container) {
			return fmt.Errorf(
				"oracle exited before listening:\n%s",
				logsOf(container))
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf(
		"oracle did not listen on %s within 30s:\n%s",
		addr, logsOf(container))
}

// handshakes reports whether a TLS handshake completes.
//
// A successful dial is not enough: Podman's port forwarder
// accepts connections before anything inside the container is
// listening, so dialling succeeds against a slapd that has
// already died. Completing a handshake proves slapd is there.
func handshakes(addr string) bool {
	d := &net.Dialer{Timeout: time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// running reports whether the container is still up.
func running(name string) bool {
	out, err := exec.Command("podman", "inspect",
		"--format", "{{.State.Running}}", name).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

// logsOf returns a container's output, trimmed.
func logsOf(name string) string {
	out, _ := exec.Command("podman", "logs",
		name).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "(no output)"
	}
	return s
}
