package store

import (
	"strings"

	"github.com/FatmanUK/olivine_ldap/internal/ldap"
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
	req *ldap.SearchRequest, who Identity,
) ldap.SearchEntry {
	e := ldap.SearchEntry{DN: ""}
	if onlyNoAttributes(req.Attributes) {
		return e
	}
	for _, a := range s.rootDSEAttrs(who) {
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

// supportedControls are the controls Olivine implements, and so
// the only ones it advertises.
//
// Advertising a control that is not implemented is worse than
// advertising none: a client reads this to decide what to send, and
// would then send something that fails.
var supportedControls = []string{
	ldap.OIDPagedResults,
}

// supportedExtensions are the extended operations Olivine
// implements, and so the only ones it advertises.
var supportedExtensions = []string{
	ldap.OIDWhoAmI,
}

// rootDSEAttrs lists everything the root DSE can carry.
//
// supportedExtension names whoami and nothing else. StartTLS is
// refused, so advertising it would be a lie; supportedFeatures is
// absent for the same reason.
//
// configContext *is* advertised, because the tree exists — but
// only to a caller who can read it. Naming a tree that answers
// noSuchObject to the reader would be a worse answer than saying
// nothing.
func (s *Store) rootDSEAttrs(
	who Identity,
) []rootDSEAttr {
	out := []rootDSEAttr{
		{"objectClass", rootDSEClasses, false},
		{"namingContexts", s.Suffixes(), true},
		{"supportedControl", supportedControls, true},
		{"supportedExtension",
			supportedExtensions, true},
		{"supportedSASLMechanisms",
			s.Mechanisms(), true},
		{"supportedLDAPVersion", []string{"3"}, true},
		{"subschemaSubentry",
			[]string{subschemaDN}, true},
		{"structuralObjectClass",
			[]string{"OpenLDAProotDSE"}, true},
	}
	if s.isRoot(who) {
		out = append(out, rootDSEAttr{
			"configContext",
			[]string{ConfigDN}, true,
		})
	}
	return out
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
