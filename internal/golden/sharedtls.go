package golden

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// sharedTLS is the one set of TLS material both implementations
// get.
//
// One set, not one each: a SASL EXTERNAL bind presents a single
// client certificate to both servers, so both have to trust the
// same authority. Generating a CA per side leaves the oracle
// rejecting Olivine's certificate with "unknown certificate
// authority", which is how this came to be shared.
var sharedTLS struct {
	once sync.Once
	dir  string
	err  error
}

// sharedTLSDir returns the directory holding the shared material,
// creating it on first use.
func sharedTLSDir() (string, error) {
	sharedTLS.once.Do(func() {
		dir, err := os.MkdirTemp("", "olivine-golden-tls-")
		if err != nil {
			sharedTLS.err = err
			return
		}
		// 0755: a container's user is a subuid of this one
		// and cannot traverse 0700, even read-only.
		if err := os.Chmod(dir, 0o755); err != nil {
			sharedTLS.err = err
			return
		}
		if err := writeKeyPair(dir); err != nil {
			sharedTLS.err = err
			return
		}
		sharedTLS.dir = dir
	})
	if sharedTLS.err != nil {
		return "", sharedTLS.err
	}
	certDir = sharedTLS.dir
	return sharedTLS.dir, nil
}

// copyTLSMaterial puts the shared material where a server can
// read it.
//
// The oracle bind-mounts one directory as /config, so its
// certificates have to live beside its slapd.conf rather than be
// referenced from elsewhere.
func copyTLSMaterial(dst string) error {
	src, err := sharedTLSDir()
	if err != nil {
		return err
	}
	for _, name := range []string{
		"ca.pem", "cert.pem", "key.pem",
		"client-cert.pem", "client-key.pem",
	} {
		err := copyFile(
			filepath.Join(src, name),
			filepath.Join(dst, name))
		if err != nil {
			return err
		}
	}
	return nil
}

// copyFile copies one file, world-readable.
func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return fmt.Errorf("reading %s: %w", from, err)
	}
	defer in.Close()
	out, err := os.OpenFile(to,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
