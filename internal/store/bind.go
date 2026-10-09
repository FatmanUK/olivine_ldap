package store

import (
	"strings"

	"github.com/FatmanUK/openldap_olivine/internal/acl"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// userPasswordAttr is where credentials live.
const userPasswordAttr = "userpassword"

// BackendBind authenticates a simple bind.
//
// RFC 4513 5.1.1: a bind with an empty name *and* empty password
// is an anonymous bind and succeeds. A bind with a name and an
// empty password is an unauthenticated bind, which RFC 4513
// 5.1.2 says a server should reject — slapd does, and so does
// this, because accepting it would authenticate anyone who knows
// a DN.
func (s *Store) BackendBind(
	req *ldap.BindRequest, who Identity,
) (Identity, ldap.Result) {
	if req.IsSASL {
		return s.saslBind(req, who)
	}
	if req.Name == "" && req.Simple == "" {
		// Anonymous: success, and the identity stays empty.
		return Identity{},
			ldap.Result{Code: ldap.Success}
	}
	if req.Simple == "" {
		return Identity{}, ldap.Result{
			Code:       ldap.UnwillingToPerform,
			Diagnostic: "unauthenticated bind rejected",
		}
	}
	// The rootdn first: it has no entry to look up, which is
	// what lets a directory be administered before it holds
	// anything.
	if id, res, isRoot := s.bindAsRoot(req); isRoot {
		return id, res
	}
	return s.checkCredentials(req, who)
}

// checkCredentials verifies a name and password.
//
// A missing entry gives invalidCredentials, not noSuchObject:
// telling an unauthenticated caller which DNs exist is a
// disclosure, and slapd does not do it either.
func (s *Store) checkCredentials(
	req *ldap.BindRequest, who Identity,
) (Identity, ldap.Result) {
	bad := ldap.Result{Code: ldap.InvalidCredentials}
	e, err := s.Get(req.Name)
	if err != nil {
		return Identity{}, bad
	}
	// auth access to userPassword, checked as the identity the
	// connection *currently* has. A policy of
	// `by self write by users read by * none` therefore stops
	// everyone binding, since at this moment the requester is
	// still anonymous — confirmed against slapd, which answers
	// invalidCredentials under exactly that configuration.
	if s.accessTo(who, e.DN, userPasswordAttr) < acl.Auth {
		return Identity{}, bad
	}
	for _, v := range e.Values {
		if v.Type != userPasswordAttr {
			continue
		}
		if VerifyPassword(v.Value, req.Simple) {
			// Both forms: the normalised DN is what an
			// access check compares, and the pretty one
			// is what whoami shows.
			return Identity{
				DN: e.DN, Pretty: e.PrettyDN,
			}, ldap.Result{Code: ldap.Success}
		}
	}
	return Identity{}, bad
}

// BackendCompare tests one attribute value.
//
// compareTrue and compareFalse are both successes: a compare
// that answers is not a compare that failed. ResultCode.
// IsSuccess says the same.
func (s *Store) BackendCompare(
	req *ldap.CompareRequest, who Identity,
) ldap.Result {
	e, err := s.Get(req.Entry)
	if err != nil {
		return resultFor(err)
	}
	at, ok := s.schema.AttributeType(req.Attribute)
	if !ok {
		return ldap.Result{
			Code:       ldap.UndefinedType,
			Diagnostic: req.Attribute,
		}
	}
	typ := strings.ToLower(canonicalName(at))
	if s.accessTo(who, e.DN, typ) < acl.Compare {
		// The entry's access, not the attribute's, decides
		// whether this reads as insufficientAccess or
		// noSuchObject. See denyResult.
		return s.refusal(who, e.DN)
	}
	rule := s.schema.EqualityRule(at)
	for _, v := range e.Values {
		if v.Type == typ && rule.Equal(v.Value, req.Value) {
			return ldap.Result{Code: ldap.CompareTrue}
		}
	}
	return ldap.Result{Code: ldap.CompareFalse}
}
