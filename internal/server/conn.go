package server

import (
	"bufio"
	"errors"
	"io"
	"net"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// conn is one client connection.
//
// One goroutine owns it for its whole life, which is why the
// resumable reader in liblber/io.c:473 has no counterpart
// here: there is no poll loop to yield to, so ReadPacket
// simply blocks.
type conn struct {
	net net.Conn
	r   *bufio.Reader
	srv *Server
	// bound is set once a bind has succeeded, and raises the
	// message-size limit as sockbuf_max_incoming does.
	bound bool
	// boundDN is the authenticated identity, empty when the
	// connection is anonymous.
	boundDN string
}

// serve reads and dispatches until the client goes away or the
// connection must be dropped.
func (c *conn) serve() {
	defer c.net.Close()
	for {
		packet, err := ber.ReadPacket(c.r, c.limit())
		if err != nil {
			c.handleReadError(err)
			return
		}
		m, err := ldap.ParseMessage(packet)
		if err != nil {
			c.handleParseError(err)
			return
		}
		if !c.dispatch(m) {
			return
		}
	}
}

// limit is the largest message this connection will accept.
// It rises once the connection has authenticated, as
// sockbuf_max_incoming does.
func (c *conn) limit() uint64 {
	if c.bound {
		return ber.MaxIncomingAuth
	}
	return ber.MaxIncomingDefault
}

// handleReadError decides whether a failed read deserves a
// diagnostic. A clean EOF is a client hanging up and says
// nothing; a framing failure is a protocol error and earns a
// notice of disconnection.
func (c *conn) handleReadError(err error) {
	if errors.Is(err, io.EOF) {
		return
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return
	}
	c.disconnect("decoding error")
}

// handleParseError answers a malformed envelope.
func (c *conn) handleParseError(err error) {
	if errors.Is(err, ldap.ErrUnexpectedPDU) {
		c.disconnect("unexpected data in PDU")
		return
	}
	c.disconnect("decoding error")
}

// disconnect sends an unsolicited notice and closes.
//
// protocolError is one of the three codes result.c's
// LDAP_UNSOLICITED_ERROR permits, so this cannot trip that
// assertion's equivalent.
func (c *conn) disconnect(why string) {
	notice, err := ldap.EncodeNotice(ldap.Result{
		Code:       ldap.ProtocolError,
		Diagnostic: why,
	})
	if err != nil {
		return
	}
	_, _ = c.net.Write(notice)
}

// send writes one response message.
func (c *conn) send(packet []byte) error {
	_, err := c.net.Write(packet)
	return err
}
