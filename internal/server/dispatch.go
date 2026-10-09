package server

import (
	"context"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// dispatch handles one message. It reports whether the
// connection should stay open.
//
// The accepted set is connection.c:1080-1089. Anything outside
// it is a protocol error that drops the connection, which is
// what slapd does rather than answering politely.
func (c *conn) dispatch(m *ldap.Message) bool {
	if !ldap.IsRequest(m.Op) {
		c.disconnect("unknown PDU")
		return false
	}
	if m.Op == ldap.ReqUnbind {
		// RFC 4511 4.3: unbind has no response.
		return false
	}
	if m.Op == ldap.ReqAbandon {
		// RFC 4511 4.11: abandon has no response, whether
		// or not it found anything.
		c.doAbandon(m)
		return true
	}
	// A bind abandons every operation already in flight, and
	// waits for them: connection.c:1633-1636 calls
	// connection_abandon( conn ) before the operation is even
	// allocated, because the identity they were authorised
	// under is about to change.
	if m.Op == ldap.ReqBind {
		c.running.cancelAll()
		c.running.wait()
		return c.answer(m, context.Background())
	}
	c.spawn(m)
	return true
}

// spawn runs one operation concurrently.
//
// The read loop carries on, so a client can pipeline requests and
// abandon a slow one — which is the whole point of tracking them.
func (c *conn) spawn(m *ldap.Message) {
	ctx := c.running.start(
		context.Background(), m.ID, m.Op)
	go func() {
		defer c.running.done(m.ID)
		c.answer(m, ctx)
	}()
}

// doAbandon cancels the operation a client named.
//
// Nothing is sent either way. An unknown message id does nothing
// at all (abandon.c:49), and bind, unbind and abandon refuse to be
// abandoned (abandon.c:66-68).
func (c *conn) doAbandon(m *ldap.Message) {
	id, err := abandonTarget(m.Body)
	if err != nil {
		return
	}
	c.running.abandon(id)
}

// abandonTarget reads the message id an abandon names.
//
// The body is the id on its own, which is why ReqAbandon is a
// primitive tag: RFC 4511 4.11 makes it
// [APPLICATION 16] MessageID.
func abandonTarget(body []byte) (int32, error) {
	return ber.Int32(body)
}

// answer sends the response for an operation that has one.
//
// The returned value says whether the connection stays open; a
// spawned operation ignores it, because only the read loop can
// decide to stop reading.
func (c *conn) answer(
	m *ldap.Message, ctx context.Context,
) bool {
	// While a SASL bind is part-way through, nothing else may
	// run: connection.c:1103-1111 answers operationsError with
	// "SASL bind in progress" for any other operation.
	if m.Op != ldap.ReqBind && c.saslInProgress() {
		return c.fail(m, ldap.Result{
			Code:       ldap.OperationsError,
			Diagnostic: "SASL bind in progress",
		})
	}
	if oid, bad := ldap.IsCriticalUnsupported(
		m.Controls); bad {
		return c.fail(m, ldap.Result{
			Code:       ldap.UnavailableCriticalExt,
			Diagnostic: "critical control " + oid,
		})
	}
	if m.Op == ldap.ReqExtended {
		return c.extended(m)
	}
	return c.operate(m, ctx)
}

// extended answers an ExtendedRequest.
//
// StartTLS is refused rather than ignored: Olivine is TLS-only
// so starttls.c is not ported, but the operation must still be
// recognised. Refusing it keeps a client's failure legible.
//
// The code is operationsError, not unwillingToPerform. Every
// Olivine connection is already TLS, which is the branch at
// starttls.c:46-48:
//
//	/* can't start TLS if it is already started */
//	if (op->o_conn->c_is_tls != 0) {
//		rs->sr_text = "TLS already started";
//		rc = LDAP_OPERATIONS_ERROR;
//
// The golden harness caught this: unwillingToPerform was a
// guess, and the diagnostic is upstream's wording verbatim.
func (c *conn) extended(m *ldap.Message) bool {
	oid := extendedOID(m.Body)
	if oid == ldap.OIDWhoAmI {
		return c.whoAmI(m)
	}
	if oid == ldap.OIDStartTLS {
		return c.fail(m, ldap.Result{
			Code:       ldap.OperationsError,
			Diagnostic: "TLS already started",
		})
	}
	return c.fail(m, ldap.Result{
		Code:       ldap.ProtocolError,
		Diagnostic: "unsupported extended operation",
	})
}

// extendedOID reads the requestName from an ExtendedRequest.
// The tag is context 0, primitive (ldap.h:511).
func extendedOID(body []byte) string {
	tag, content, err := ber.NewDecoder(body).Next()
	if err != nil || tag != ldap.TagExopReqOID {
		return ""
	}
	return string(content)
}

// fail sends an error result under the right response tag and
// reports whether the connection stays open.
func (c *conn) fail(m *ldap.Message, r ldap.Result) bool {
	packet, err := ldap.EncodeResult(
		m.ID, responseTag(m.Op), r)
	if err != nil {
		return false
	}
	return c.send(packet) == nil
}

// whoAmI answers RFC 4532.
//
// The identity is the connection's, so this is the one operation
// that tells an administrator what a bind actually did — which is
// why it is worth implementing even though nothing else needs an
// extended operation.
func (c *conn) whoAmI(m *ldap.Message) bool {
	value, has := ldap.WhoAmIValue(c.identity())
	packet, err := ldap.EncodeExtendedResponse(
		m.ID, ldap.Result{Code: ldap.Success}, value, has)
	if err != nil {
		return false
	}
	return c.send(packet) == nil
}
