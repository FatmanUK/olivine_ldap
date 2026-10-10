package server

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/FatmanUK/olivine_ldap/internal/ber"
	"github.com/FatmanUK/olivine_ldap/internal/gss"
	"github.com/FatmanUK/olivine_ldap/internal/ldap"
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
	// writes serialises sending, because operations run
	// concurrently. Two goroutines writing a message each would
	// interleave their BER and corrupt the stream — the single
	// worst bug this concurrency could introduce, and the
	// cheapest to prevent.
	writes sync.Mutex
	// running tracks the operations in flight, so abandon has
	// something to cancel.
	running *inflight
	// bound is set once a bind has succeeded, and raises the
	// message-size limit as sockbuf_max_incoming does.
	bound bool
	// boundDN is the authenticated identity, empty when the
	// connection is anonymous. boundPretty is the same DN in
	// the form to show a client; see ldap.Identity.
	boundDN     string
	boundPretty string
	// saslMech is the mechanism of a SASL bind in progress,
	// empty when none is. Guarded by saslMu, because the read
	// loop sets it while a spawned operation may read it.
	saslMu   sync.Mutex
	saslMech string
	// gss is the GSSAPI exchange's state, which has to survive
	// between bind requests. One per connection, discarded
	// whenever the mechanism changes, and guarded by saslMu
	// for the same reason saslMech is.
	gss *gss.Context
}

// saslInProgress reports whether a multi-step SASL bind is
// part-way through.
func (c *conn) saslInProgress() bool {
	c.saslMu.Lock()
	defer c.saslMu.Unlock()
	return c.saslMech != ""
}

// setSASL records or clears the in-progress mechanism, and
// discards any mechanism state along with it.
func (c *conn) setSASL(mech string) {
	c.saslMu.Lock()
	c.saslMech = mech
	if mech == "" {
		c.gss = nil
	}
	c.saslMu.Unlock()
}

// gssContext is the connection's GSSAPI state, created on the
// first step of an exchange.
func (c *conn) gssContext() *gss.Context {
	c.saslMu.Lock()
	defer c.saslMu.Unlock()
	if c.gss == nil {
		c.gss = &gss.Context{}
	}
	return c.gss
}

// serve reads and dispatches until the client goes away or the
// connection must be dropped.
//
// Operations run concurrently, one goroutine each, which is what
// gives abandon something to abandon — and what a client pipelining
// requests expects. The read loop itself stays single-threaded:
// only one goroutine ever touches the BER reader.
func (c *conn) serve() {
	defer c.net.Close()
	defer c.running.wait()
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

// identity is who this connection currently is.
//
// At bind time this is still the previous identity, usually
// anonymous, which is what access control sees when it checks
// auth on userPassword.
func (c *conn) identity() ldap.Identity {
	return ldap.Identity{
		DN: c.boundDN, Pretty: c.boundPretty,
	}
}

// send writes one response message.
//
// Under the write mutex, and one whole message per call, so a
// search streaming entries cannot have another operation's result
// spliced into the middle of one.
func (c *conn) send(packet []byte) error {
	c.writes.Lock()
	defer c.writes.Unlock()
	_, err := c.net.Write(packet)
	return err
}
