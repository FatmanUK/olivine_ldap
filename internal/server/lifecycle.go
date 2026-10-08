package server

import "net"

// accept takes the next connection.
func (s *Server) accept() (net.Conn, error) {
	s.mu.Lock()
	l := s.listener
	s.mu.Unlock()
	if l == nil {
		return nil, net.ErrClosed
	}
	return l.Accept()
}

// isClosed reports whether Close has been called.
func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Close stops accepting and waits for connections in flight.
//
// Crash-only architecture means shutdown is not a feature to
// be relied on: the server must survive being killed at any
// point. This exists so tests can stop a Server, not so that
// operators have a graceful path to depend on.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	l := s.listener
	s.mu.Unlock()

	var err error
	if l != nil {
		err = l.Close()
	}
	s.wg.Wait()
	return err
}
