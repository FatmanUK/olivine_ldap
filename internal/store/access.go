package store

import (
	"github.com/FatmanUK/openldap_olivine/internal/acl"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// SetPolicy installs the access policy.
//
// A Store with no policy grants read on everything, which is
// slapd's default when no access directive is configured
// (frontend.c:99, be_dfltaccess = ACL_READ).
func (s *Store) SetPolicy(p *acl.Policy) {
	s.policy = p
}

// policyOrDefault returns the policy in force.
func (s *Store) policyOrDefault() *acl.Policy {
	if s.policy == nil {
		return acl.NewPolicy()
	}
	return s.policy
}

// Identity is re-exported so callers need not name two types
// for one thing.
type Identity = ldap.Identity

// accessTo reports the level the asker has for one attribute.
func (s *Store) accessTo(
	who Identity, targetDN, attribute string,
) acl.Level {
	return s.policyOrDefault().Level(acl.Request{
		TargetDN:  targetDN,
		Attribute: attribute,
		BoundDN:   who.DN,
	})
}

// denyResult turns a refusal into the result slapd gives.
//
// The distinction is what `disclose` is for, and the oracle drew
// it sharply: with disclose granted, an unreadable entry answers
// insufficientAccess (50) and so admits it exists; without it,
// noSuchObject (32) and the entry stays hidden.
//
// The level passed in must be the access to the **entry**, not to
// whichever attribute was refused. Under
// `access to attrs=sn by * none` followed by
// `access to * by * read`, a compare of sn is refused while the
// entry is plainly readable, and slapd answers
// insufficientAccess: once the requester can see the entry,
// pretending it does not exist would be a lie it has already
// disproved. Passing the attribute's own level here gives
// noSuchObject and differs from the C.
func denyResult(entryLevel acl.Level) ldap.Result {
	if entryLevel >= acl.Disclose {
		return ldap.Result{Code: ldap.InsufficientAccess}
	}
	return ldap.Result{Code: ldap.NoSuchObject}
}

// refusal builds the result for a denial on an entry, reading the
// entry's own access to choose between hiding and admitting.
func (s *Store) refusal(
	who Identity, entryDN string,
) ldap.Result {
	return denyResult(
		s.accessTo(who, entryDN, acl.EntryAttribute))
}

// denyWrite checks write access to an entry, reporting the
// refusal to send when it is denied.
func (s *Store) denyWrite(
	who Identity, rawDN string,
) (ldap.Result, bool) {
	return s.deny(who, rawDN, acl.EntryAttribute, acl.Write)
}

// denyWriteAttr checks write access to one attribute.
func (s *Store) denyWriteAttr(
	who Identity, rawDN, attribute string,
) (ldap.Result, bool) {
	typ, err := s.canonicalType(attribute)
	if err != nil {
		return resultFor(err), false
	}
	return s.deny(who, rawDN, typ, acl.Write)
}

// deny resolves a DN and checks one level, returning the result
// to send and whether access was granted.
func (s *Store) deny(
	who Identity, rawDN, attribute string,
	need acl.Level,
) (ldap.Result, bool) {
	norm, _, err := s.normalise(rawDN)
	if err != nil {
		return resultFor(err), false
	}
	if s.accessTo(who, norm, attribute) >= need {
		return ldap.Result{}, true
	}
	// The entry's access decides how the refusal reads, even
	// when it was an attribute that was refused.
	return s.refusal(who, norm), false
}

// requireAuthenticatedUpdate refuses an update from an anonymous
// connection.
//
// slapd does this before consulting the ACLs and answers
// strongerAuthRequired (8), not insufficientAccess (50) — an
// anonymous add of a schema-valid entry under default ACLs gives
// "Strong(er) authentication required". It is a restriction on
// the connection rather than a judgement about the target, which
// is why the code differs.
func requireAuthenticatedUpdate(
	who Identity,
) (ldap.Result, bool) {
	if !who.Anonymous() {
		return ldap.Result{}, true
	}
	return ldap.Result{
		Code:       ldap.StrongerAuthRequired,
		Diagnostic: "modifications require authentication",
	}, false
}
