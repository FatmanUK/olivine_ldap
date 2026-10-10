package golden

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"

	"github.com/FatmanUK/olivine_ldap/internal/server"
)

// Backend is what StartOlivine attaches, if anything. A nil
// Backend leaves every operation unwillingToPerform, which is
// what the protocol-only scripts want.
type Backend = server.Backend

// Olivine is this project's server, running in-process.
//
// In-process rather than in a container: the whole point of
// the comparison is that one side is the code under test, so
// a panic surfaces as a test failure with a stack rather than
// as a dead container.
type Olivine struct {
	Addr    string
	srv     *server.Server
	dir     string
	backend Backend
}

// StartOlivine listens on an ephemeral port with no backend.
func StartOlivine() (*Olivine, error) {
	return StartOlivineWith(nil)
}

// StartOlivineWith listens with the given backend attached.
func StartOlivineWith(b Backend) (*Olivine, error) {
	dir, err := os.MkdirTemp("", "olivine-under-test-")
	if err != nil {
		return nil, err
	}
	o := &Olivine{dir: dir, backend: b}
	// The same material the oracle gets, so a SASL EXTERNAL
	// bind presents one certificate to both.
	shared, err := sharedTLSDir()
	if err != nil {
		o.Stop()
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(
		filepath.Join(shared, "cert.pem"),
		filepath.Join(shared, "key.pem"))
	if err != nil {
		o.Stop()
		return nil, err
	}
	if err := o.listen(pair); err != nil {
		o.Stop()
		return nil, err
	}
	return o, nil
}

// listen starts the server on an ephemeral port.
func (o *Olivine) listen(pair tls.Certificate) error {
	// Verify a client certificate if one is offered, as the
	// oracle's `TLSVerifyClient try` does.
	clientCAs, err := clientCAPool()
	if err != nil {
		return err
	}
	s, err := server.New(server.Config{
		Addr:      "127.0.0.1:0",
		Backend:   o.backend,
		ClientCAs: clientCAs,
		TLS: &tls.Config{
			Certificates: []tls.Certificate{pair},
			MinVersion:   tls.VersionTLS12,
		},
	})
	if err != nil {
		return err
	}
	if err := s.Listen(); err != nil {
		return err
	}
	addr := s.Addr()
	if addr == nil {
		return fmt.Errorf("olivine did not bind")
	}
	o.srv, o.Addr = s, addr.String()
	go func() { _ = s.Serve() }()
	return nil
}

// Stop shuts the server down and removes its scratch files.
func (o *Olivine) Stop() {
	if o.srv != nil {
		_ = o.srv.Close()
		o.srv = nil
	}
	if o.dir != "" {
		_ = os.RemoveAll(o.dir)
		o.dir = ""
	}
}
