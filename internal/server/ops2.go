package server

import "github.com/FatmanUK/openldap_olivine/internal/ldap"

// doAdd creates an entry.
func (c *conn) doAdd(m *ldap.Message) bool {
	req, err := ldap.ParseAddRequest(m.Body)
	if err != nil {
		return c.protocolError(m, err)
	}
	return c.fail(m,
		c.srv.backend.Add(req, c.identity()))
}

// doDelete removes an entry.
//
// A DelRequest's body is the DN on its own, not wrapped in a
// sequence: RFC 4511 4.8 makes it [APPLICATION 10] LDAPDN, which
// is why ReqDelete is a primitive tag (0x4a) where most requests
// are constructed.
func (c *conn) doDelete(m *ldap.Message) bool {
	return c.fail(m, c.srv.backend.Delete(
		string(m.Body), c.identity()))
}

// doModify applies modifications.
func (c *conn) doModify(m *ldap.Message) bool {
	req, err := ldap.ParseModifyRequest(m.Body)
	if err != nil {
		return c.protocolError(m, err)
	}
	return c.fail(m,
		c.srv.backend.Modify(req, c.identity()))
}

// doCompare tests one attribute value.
func (c *conn) doCompare(m *ldap.Message) bool {
	req, err := ldap.ParseCompareRequest(m.Body)
	if err != nil {
		return c.protocolError(m, err)
	}
	return c.fail(m,
		c.srv.backend.Compare(req, c.identity()))
}

// doModDN renames or moves an entry.
func (c *conn) doModDN(m *ldap.Message) bool {
	req, err := ldap.ParseModDNRequest(m.Body)
	if err != nil {
		return c.protocolError(m, err)
	}
	return c.fail(m,
		c.srv.backend.ModDN(req, c.identity()))
}
