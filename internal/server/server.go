package server

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
)

// ErrNoTLS is returned when a Server is configured without
// TLS. There is no cleartext listener and no STARTTLS, so a
// missing certificate is a configuration error and not a
// reason to fall back.
var ErrNoTLS = errors.New(
	"server: TLS configuration is required")

// Config configures a Server.
type Config struct {
	// Addr is the listen address, host:port.
	Addr string
	// TLS must be set. See ErrNoTLS.
	TLS *tls.Config
	// Backend answers operations. A nil Backend makes every
	// operation unwillingToPerform, which is what the server
	// did before any database existed.
	Backend Backend
	// ClientCAs, when set, makes the server *request* a client
	// certificate and verify it against these authorities. A
	// client that presents none is still served — the
	// certificate is an identity for SASL EXTERNAL to bind as,
	// not an admission ticket. That is what slapd's
	// `TLSVerifyClient try` does, and demanding one would lock
	// out every client that binds by password.
	ClientCAs *x509.CertPool
}

// Server accepts LDAP connections over TLS.
type Server struct {
	cfg     Config
	backend Backend

	mu       sync.Mutex
	listener net.Listener
	closed   bool
	wg       sync.WaitGroup
}

// New returns a Server for cfg.
func New(cfg Config) (*Server, error) {
	if cfg.TLS == nil {
		return nil, ErrNoTLS
	}
	if cfg.ClientCAs != nil {
		// Clone, so a caller's tls.Config is not mutated
		// under it.
		tc := cfg.TLS.Clone()
		tc.ClientCAs = cfg.ClientCAs
		// Verify if given, require nothing: see ClientCAs.
		tc.ClientAuth = tls.VerifyClientCertIfGiven
		cfg.TLS = tc
	}
	return &Server{cfg: cfg, backend: cfg.Backend}, nil
}

// Listen opens the listening socket without serving, so a
// caller can learn the bound address before accepting. Useful
// when the port is chosen by the kernel.
func (s *Server) Listen() error {
	l, err := tls.Listen("tcp", s.cfg.Addr, s.cfg.TLS)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		l.Close()
		return net.ErrClosed
	}
	s.listener = l
	return nil
}

// Addr returns the bound address, or nil before Listen.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Serve accepts connections until Close. It calls Listen first
// if that has not happened.
func (s *Server) Serve() error {
	if s.Addr() == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	for {
		nc, err := s.accept()
		if err != nil {
			if s.isClosed() {
				return nil
			}
			return err
		}
		s.wg.Add(1)
		go s.handle(nc)
	}
}

// handle serves one connection and accounts for it.
func (s *Server) handle(nc net.Conn) {
	defer s.wg.Done()
	c := &conn{
		net:     nc,
		r:       bufio.NewReader(nc),
		srv:     s,
		running: newInflight(),
	}
	c.serve()
}
