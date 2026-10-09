package store

import (
	"bytes"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// bindPlain authenticates a SASL PLAIN credential.
//
// RFC 4616 2: the credential is
//
//	authzid NUL authcid NUL passwd
//
// NUL-separated, not length-prefixed, and the authzid is usually
// empty. A non-empty authzid asks to act as somebody else, which
// is proxy authorization — refused here for the same reason
// EXTERNAL refuses a credential.
//
// PLAIN is safe only on an encrypted transport, which RFC 4616 2
// requires and Olivine has unconditionally: there is no cleartext
// listener for it to be exposed on.
func (s *Store) bindPlain(
	req *ldap.BindRequest, who Identity,
) (Identity, ldap.Result) {
	authzid, authcid, passwd, ok := splitPlain(
		req.Credentials)
	if !ok {
		return Identity{}, ldap.Result{
			Code:       ldap.InvalidCredentials,
			Diagnostic: "malformed PLAIN credential",
		}
	}
	if authzid != "" && authzid != authcid {
		return Identity{}, ldap.Result{
			Code: ldap.UnwillingToPerform,
			Diagnostic: "proxy authorization not " +
				"supported",
		}
	}
	if authcid == "" || passwd == "" {
		// An empty password is an unauthenticated bind by
		// another route, and is refused for the same reason
		// RFC 4513 5.1.2 gives.
		return Identity{}, ldap.Result{
			Code: ldap.InvalidCredentials,
		}
	}
	// The authcid is a DN here, so the check is the one a simple
	// bind makes.
	return s.BackendBind(&ldap.BindRequest{
		Version: ldap.Version3,
		Name:    authcid,
		Simple:  passwd,
	}, who)
}

// splitPlain separates the three NUL-delimited fields.
func splitPlain(
	cred []byte,
) (authzid, authcid, passwd string, ok bool) {
	parts := bytes.SplitN(cred, []byte{0}, 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return string(parts[0]), string(parts[1]),
		string(parts[2]), true
}
