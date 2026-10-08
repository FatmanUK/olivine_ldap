package golden

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// containerPort is where slapd listens inside the container.
// Above 1024, because the container runs unprivileged.
const containerPort = 10636

// Oracle is a running slapd, built from the pinned submodule
// and reachable over TLS.
type Oracle struct {
	Addr      string
	container string
	dir       string
}

// repoRoot finds the repository root.
//
// `go test` runs with the package directory as its working
// directory, so a relative path to the submodule does not
// work from here.
func repoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse",
		"--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf(
			"finding repository root: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// imageTag names the oracle image. It carries the upstream
// release, so a stale image cannot pass for a current one.
func imageTag() (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", err
	}
	out, err := exec.Command("git", "-C",
		filepath.Join(root, "openldap"),
		"describe", "--tags", "--always").Output()
	if err != nil {
		return "", fmt.Errorf(
			"reading submodule tag: %w", err)
	}
	tag := strings.TrimSpace(string(out))
	return "olivine-oracle:" + tag, nil
}

// StartOracle runs slapd in a container on a host port with no
// access directives, so the default of read applies.
func StartOracle(port int) (*Oracle, error) {
	return StartOracleWith(port, "")
}

// StartOracleWith runs slapd with extra configuration appended,
// which is how the access comparison gives both implementations
// the same policy.
//
// Configuration is generated per run and bind-mounted
// read-only; the database lives inside the container, so
// nothing on the host has to be writable by the container's
// uid. Rootless Podman maps that uid to a subuid, and a
// bind-mounted writable directory is the usual way this goes
// wrong.
func StartOracleWith(
	port int, extra string,
) (*Oracle, error) {
	image, err := imageTag()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "olivine-oracle-")
	if err != nil {
		return nil, err
	}
	// MkdirTemp creates the directory 0700. The container
	// runs as its own user, which rootless Podman maps to a
	// subuid of the host user, so it cannot traverse a 0700
	// directory even through a read-only bind mount — slapd
	// exits before listening and, at -d 0, says nothing
	// about why.
	if err := os.Chmod(dir, 0o755); err != nil {
		return nil, err
	}
	o := &Oracle{
		Addr: fmt.Sprintf("127.0.0.1:%d", port),
		dir:  dir,
	}
	if err := writeOracleConfig(dir, extra); err != nil {
		o.Stop()
		return nil, err
	}
	if err := o.run(image, port); err != nil {
		o.Stop()
		return nil, err
	}
	return o, nil
}

// run starts the container and waits for the port to answer.
func (o *Oracle) run(image string, port int) error {
	name := fmt.Sprintf("olivine-oracle-%d", port)
	// Remove a container left by an interrupted run.
	_ = exec.Command("podman", "rm", "-f", name).Run()

	// Deliberately no --rm: a container that exits during
	// startup takes its logs with it, and Logs() is the only
	// way to find out why. Stop() removes it instead.
	args := []string{
		"run", "--detach",
		"--name", name,
		"--publish", fmt.Sprintf("127.0.0.1:%d:%d",
			port, containerPort),
		"--volume", o.dir + ":/config:ro",
		image,
		// The port must be explicit. "ldaps:///" defaults
		// to 636, and the container runs unprivileged, so
		// slapd dies with
		// "daemon: bind(6) failed errno=13" and the
		// published port never answers.
		"-h", fmt.Sprintf("ldaps://0.0.0.0:%d/",
			containerPort),
		"-f", "/config/slapd.conf",
		"-d", "0",
	}
	out, err := exec.Command("podman", args...).
		CombinedOutput()
	if err != nil {
		return fmt.Errorf("podman run: %w: %s", err, out)
	}
	o.container = name
	return waitForPort(o.Addr, name)
}

// Stop removes the container and the generated config.
func (o *Oracle) Stop() {
	if o.container != "" {
		_ = exec.Command("podman", "rm", "-f",
			o.container).Run()
		o.container = ""
	}
	if o.dir != "" {
		_ = os.RemoveAll(o.dir)
		o.dir = ""
	}
}

// Logs returns the container's output, for when a start fails.
func (o *Oracle) Logs() string {
	if o.container == "" {
		return ""
	}
	out, _ := exec.Command("podman", "logs",
		o.container).CombinedOutput()
	return string(out)
}

// configPath is where the generated slapd.conf lands.
func (o *Oracle) configPath() string {
	return filepath.Join(o.dir, "slapd.conf")
}
