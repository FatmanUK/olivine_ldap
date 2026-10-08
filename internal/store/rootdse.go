package store

import (
	"strings"

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

// rootDSEAttr is one candidate attribute of the root DSE.
type rootDSEAttr struct {
	Type        string
	Values      []string
	Operational bool
}

// rootDSE builds the root DSE for a base-scope search of "".
//
// Only base scope: slapd answers noSuchObject for a one-level or
// subtree search from an empty base, so the root DSE is not the
// top of a walkable tree.
func (s *Store) rootDSE(
	req *ldap.SearchRequest,
) ldap.SearchEntry {
	e := ldap.SearchEntry{DN: ""}
	if onlyNoAttributes(req.Attributes) {
		return e
	}
	for _, a := range s.rootDSEAttrs() {
		if !rootDSEWanted(req.Attributes, a) {
			continue
		}
		e.Attributes = append(e.Attributes,
			ldap.AttributeChange{
				Type: a.Type, Values: a.Values,
			})
	}
	return e
}

// rootDSEAttrs lists everything the root DSE can carry.
//
// Deliberately absent: supportedExtension, because Olivine
// implements no extended operation and advertising StartTLS while
// refusing it would be a lie; supportedControl and
// supportedFeatures, for the same reason; and configContext,
// because cn=config does not exist yet.
func (s *Store) rootDSEAttrs() []rootDSEAttr {
	return []rootDSEAttr{
		{"objectClass", rootDSEClasses, false},
		{"namingContexts", s.Suffixes(), true},
		{"supportedLDAPVersion", []string{"3"}, true},
		{"subschemaSubentry",
			[]string{subschemaDN}, true},
		{"structuralObjectClass",
			[]string{"OpenLDAProotDSE"}, true},
	}
}

// rootDSEWanted reports whether one root DSE attribute belongs in
// the reply.
//
// An explicitly named attribute is returned whatever its usage:
// slapd answers a request for namingContexts alone with
// namingContexts, even though it is operational and a plain search
// withholds it. Honouring only "+" leaves a client that asks by
// name with an empty entry, which is how the container smoke test
// first failed.
func rootDSEWanted(
	requested []string, a rootDSEAttr,
) bool {
	for _, want := range requested {
		if strings.EqualFold(want, a.Type) {
			return true
		}
	}
	if a.Operational {
		return wantsOperational(requested)
	}
	return wantsUser(requested)
}

// isRootDSERequest reports whether req asks for the root DSE.
func isRootDSERequest(req *ldap.SearchRequest) bool {
	return req.BaseObject == ""
}
