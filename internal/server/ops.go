package server

import (
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// operate dispatches one request to the backend.
//
// Returns whether the connection stays open.
func (c *conn) operate(m *ldap.Message) bool {
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
		return c.doSearch(m)
	case ldap.ReqAdd:
		return c.doAdd(m)
	case ldap.ReqDelete:
		return c.doDelete(m)
	case ldap.ReqModify:
		return c.doModify(m)
	case ldap.ReqCompare:
		return c.doCompare(m)
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
	} else {
		// A failed bind drops any previous identity: RFC
		// 4513 4.4.2 makes the connection anonymous.
		c.bound = false
		c.boundDN = ""
	}
	return c.fail(m, res)
}

// doSearch runs a search, sending entries then the result.
func (c *conn) doSearch(m *ldap.Message) bool {
	req, err := ldap.ParseSearchRequest(m.Body)
	if err != nil {
		return c.protocolError(m, err)
	}
	if !req.Scope.Valid() {
		return c.fail(m, ldap.Result{
			Code:       ldap.ProtocolError,
			Diagnostic: "invalid scope",
		})
	}
	entries, res := c.srv.backend.Search(
		req, c.identity())
	for _, e := range entries {
		packet, err := ldap.EncodeSearchEntry(m.ID, e)
		if err != nil {
			return false
		}
		if c.send(packet) != nil {
			return false
		}
	}
	return c.fail(m, res)
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
