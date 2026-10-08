package store

import (
	"strings"

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
	req *ldap.BindRequest,
) ldap.Result {
	if req.IsSASL {
		// SASL is still an open question; refusing by name
		// is more useful than a generic failure.
		return ldap.Result{
			Code: ldap.AuthMethodNotSupported,
			Diagnostic: "SASL mechanism " +
				req.Mechanism + " not supported",
		}
	}
	if req.Name == "" && req.Simple == "" {
		return ldap.Result{Code: ldap.Success}
	}
	if req.Simple == "" {
		return ldap.Result{
			Code:       ldap.UnwillingToPerform,
			Diagnostic: "unauthenticated bind rejected",
		}
	}
	return s.checkCredentials(req)
}

// checkCredentials verifies a name and password.
//
// A missing entry gives invalidCredentials, not noSuchObject:
// telling an unauthenticated caller which DNs exist is a
// disclosure, and slapd does not do it either.
func (s *Store) checkCredentials(
	req *ldap.BindRequest,
) ldap.Result {
	e, err := s.Get(req.Name)
	if err != nil {
		return ldap.Result{Code: ldap.InvalidCredentials}
	}
	for _, v := range e.Values {
		if v.Type != userPasswordAttr {
			continue
		}
		if VerifyPassword(v.Value, req.Simple) {
			return ldap.Result{Code: ldap.Success}
		}
	}
	return ldap.Result{Code: ldap.InvalidCredentials}
}

// BackendCompare tests one attribute value.
//
// compareTrue and compareFalse are both successes: a compare
// that answers is not a compare that failed. ResultCode.
// IsSuccess says the same.
func (s *Store) BackendCompare(
	req *ldap.CompareRequest,
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
	want := NormaliseValue(s.schema, at, req.Value)
	for _, v := range e.Values {
		if v.Type == typ && v.Norm == want {
			return ldap.Result{Code: ldap.CompareTrue}
		}
	}
	return ldap.Result{Code: ldap.CompareFalse}
}
