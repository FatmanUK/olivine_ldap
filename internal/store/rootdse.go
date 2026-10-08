package store

import (
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// rootDSEClasses are the object classes slapd gives the root DSE.
//
// OpenLDAProotDSE is upstream's own class, not an RFC one. It is
// carried because behaviour compatibility is the goal and a client
// may key on it; nothing in RFC 4512 specifies what the root DSE's
// objectClass should be.
var rootDSEClasses = []string{"top", "OpenLDAProotDSE"}

// subschemaDN is where the schema is published.
const subschemaDN = "cn=Subschema"

// rootDSE builds the root DSE for a base-scope search of "".
//
// Only base scope: slapd answers noSuchObject (32) for a one-level
// or subtree search from an empty base, so the root DSE is not the
// top of a walkable tree.
//
// The attributes split by usage, as they do everywhere: a plain
// search returns objectClass alone, and the rest arrive only with
// `+` or by name. That is why slapd's `+` output carries no
// objectClass line at all.
func (s *Store) rootDSE(
	req *ldap.SearchRequest,
) ldap.SearchEntry {
	e := ldap.SearchEntry{DN: ""}
	add := func(typ string, values ...string) {
		e.Attributes = append(e.Attributes,
			ldap.AttributeChange{
				Type: typ, Values: values,
			})
	}
	if wantsUser(req.Attributes) {
		add("objectClass", rootDSEClasses...)
	}
	if !wantsOperational(req.Attributes) {
		return e
	}
	// Deliberately absent: supportedExtension, because
	// Olivine implements no extended operation and advertising
	// StartTLS while refusing it would be a lie; supportedControl
	// and supportedFeatures, for the same reason; and
	// configContext, because cn=config does not exist yet.
	add("namingContexts", s.Suffixes()...)
	add("supportedLDAPVersion", "3")
	add("subschemaSubentry", subschemaDN)
	add("entryDN", "")
	add("structuralObjectClass", "OpenLDAProotDSE")
	return e
}

// isRootDSERequest reports whether req asks for the root DSE.
func isRootDSERequest(req *ldap.SearchRequest) bool {
	return req.BaseObject == ""
}
