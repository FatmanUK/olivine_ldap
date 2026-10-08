package server

import (
	"bufio"
	"crypto/tls"
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
}

// Server accepts LDAP connections over TLS.
type Server struct {
	cfg Config

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
	return &Server{cfg: cfg}, nil
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
		net: nc,
		r:   bufio.NewReader(nc),
		srv: s,
	}
	c.serve()
}
