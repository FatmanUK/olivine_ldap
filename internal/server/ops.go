package server

import (
	"context"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// operate dispatches one request to the backend.
//
// Returns whether the connection stays open.
func (c *conn) operate(
	m *ldap.Message, ctx context.Context,
) bool {
	if c.srv.backend == nil {
		return c.fail(m, ldap.Result{
			Code:       ldap.UnwillingToPerform,
			Diagnostic: "no backend configured",
		})
	}
	switch m.Op {
	case ldap.ReqBind:
		return c.doBind(m)
	case ldap.ReqSearch:
		return c.doSearch(m, ctx)
	case ldap.ReqAdd:
		return c.doAdd(m)
	case ldap.ReqDelete:
		return c.doDelete(m)
	case ldap.ReqModify:
		return c.doModify(m)
	case ldap.ReqCompare:
		return c.doCompare(m)
	case ldap.ReqModDN:
		return c.doModDN(m)
	}
	return c.fail(m, ldap.Result{
		Code:       ldap.UnwillingToPerform,
		Diagnostic: "operation not implemented",
	})
}

// doBind authenticates the connection.
func (c *conn) doBind(m *ldap.Message) bool {
	req, err := ldap.ParseBindRequest(m.Body)
	if err != nil {
		return c.protocolError(m, err)
	}
	c.beginBind(req)
	// RFC 4511 4.2: a version other than 3 is
	// protocolError. Olivine serves LDAPv3 only.
	if req.Version != ldap.Version3 {
		return c.fail(m, ldap.Result{
			Code:       ldap.ProtocolError,
			Diagnostic: "version not supported",
		})
	}
	who, res := c.srv.backend.Bind(req, c.identity())
	if res.Code == ldap.Success {
		c.bound = true
		// The backend's normalised DN, not req.Name: a
		// client's own spelling will not compare against
		// stored entries.
		c.boundDN = who.DN
		c.boundPretty = who.Pretty
		c.setSASL("")
	}
	if res.Code != ldap.SASLBindInProgress {
		c.setSASL("")
	}
	return c.bindResult(m, res)
}

// doSearch runs a search, sending entries then the result.
//
// An abandoned search sends nothing at all — not the entries it had
// found and not a result. RFC 4511 4.11 gives an abandoned
// operation no response, and slapd's result.c intercepts the reply
// of an operation marked o_abandon for the same reason.
func (c *conn) doSearch(
	m *ldap.Message, ctx context.Context,
) bool {
	req, err := ldap.ParseSearchRequest(m.Body)
	if err != nil {
		return c.protocolError(m, err)
	}
	req.Controls = m.Controls
	req.Context = ctx
	if !req.Scope.Valid() {
		return c.fail(m, ldap.Result{
			Code:       ldap.ProtocolError,
			Diagnostic: "invalid scope",
		})
	}
	entries, res, controls := c.srv.backend.Search(
		req, c.identity())
	if abandoned(ctx) {
		return true
	}
	for _, e := range entries {
		packet, err := ldap.EncodeSearchEntry(m.ID, e)
		if err != nil {
			return false
		}
		if c.send(packet) != nil {
			return false
		}
	}
	return c.result(m, res, controls)
}

// abandoned reports whether an operation was cancelled.
func abandoned(ctx context.Context) bool {
	return ctx != nil && ctx.Err() != nil
}

// result sends a result message carrying response controls.
func (c *conn) result(
	m *ldap.Message, r ldap.Result,
	controls []ldap.Control,
) bool {
	packet, err := ldap.EncodeResultWithControls(
		m.ID, responseTag(m.Op), r, controls)
	if err != nil {
		return false
	}
	return c.send(packet) == nil
}

// protocolError answers a request that would not decode.
func (c *conn) protocolError(
	m *ldap.Message, err error,
) bool {
	return c.fail(m, ldap.Result{
		Code:       ldap.ProtocolError,
		Diagnostic: err.Error(),
	})
}

// beginBind resets the connection's authentication state before a
// bind runs.
//
// Every bind drops the current identity first, as
// connection2anonymous does in bind.c:65: a bind that fails must
// not leave the previous identity in place.
func (c *conn) beginBind(req *ldap.BindRequest) {
	c.bound = false
	c.boundDN = ""
	c.boundPretty = ""
	// A simple bind cancels any SASL exchange under way
	// (bind.c:285-296); a SASL bind that changes mechanism
	// mid-exchange resets it (bind.c:266-272).
	c.trackSASL(req)
	// The transport's identity, which EXTERNAL binds as. Only
	// the server can see it.
	req.External = peerDN(c.net)
	if req.IsSASL {
		req.GSS = c.gssContext()
	}
}

// trackSASL keeps the connection's SASL state in step with the
// bind that has just arrived.
func (c *conn) trackSASL(req *ldap.BindRequest) {
	if !req.IsSASL {
		// Not SASL: cancel anything in progress.
		c.setSASL("")
		return
	}
	c.saslMu.Lock()
	defer c.saslMu.Unlock()
	if c.saslMech != "" && c.saslMech != req.Mechanism {
		// The mechanism changed between steps, so the
		// exchange so far is discarded rather than carried
		// into a different mechanism.
		c.saslMech = req.Mechanism
		c.gss = nil
		return
	}
	c.saslMech = req.Mechanism
}

// bindResult sends a bind response, carrying serverSaslCreds when
// the mechanism has more to say.
func (c *conn) bindResult(
	m *ldap.Message, r ldap.Result,
) bool {
	packet, err := ldap.EncodeBindResponse(
		m.ID, r, r.SASLCreds, r.SASLCreds != nil)
	if err != nil {
		return false
	}
	return c.send(packet) == nil
}
