package server

import (
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
	// A bind abandons every operation already in flight.
	// connection.c:1633-1636 calls connection_abandon( conn )
	// before the operation is even allocated.
	if m.Op == ldap.ReqBind {
		c.abandonAll()
	}
	if m.Op == ldap.ReqAbandon {
		// RFC 4511 4.11: abandon has no response either.
		return true
	}
	return c.answer(m)
}

// answer sends the response for an operation that has one.
func (c *conn) answer(m *ldap.Message) bool {
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
	return c.operate(m)
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

// abandonAll drops operations in flight. Nothing runs
// concurrently yet, so this is a placeholder with a name
// rather than a silent omission; it gains a body at step 8.
func (c *conn) abandonAll() {}
