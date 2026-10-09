package store

import (
	"errors"
	"strings"

	"github.com/FatmanUK/openldap_olivine/internal/gss"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// SetGSSAcceptor installs the Kerberos service keys, which is
// what turns GSSAPI on.
func (s *Store) SetGSSAcceptor(a *gss.Acceptor) {
	s.gss = a
}

// bindGSSAPI runs one step of a SASL GSSAPI exchange.
//
// Three steps, and the middle one carries no credential at all —
// see the package comment on internal/gss, which records the
// exchange as captured from upstream's own client rather than as
// read from RFC 4752.
func (s *Store) bindGSSAPI(
	req *ldap.BindRequest,
) (Identity, ldap.Result) {
	if s.gss == nil {
		return Identity{}, ldap.Result{
			Code: ldap.AuthMethodNotSupported,
			Diagnostic: "GSSAPI is not configured: " +
				"no keytab",
		}
	}
	if req.GSS == nil {
		// No connection owns this request, so there is
		// nowhere to keep a multi-step exchange.
		return Identity{}, ldap.Result{
			Code:       ldap.Other,
			Diagnostic: "no SASL context",
		}
	}
	reply, done, err := s.gss.Step(
		req.GSS, req.Credentials, req.HasCredentials)
	if err != nil {
		return Identity{}, gssFailure(err)
	}
	if !done {
		return Identity{}, ldap.Result{
			Code:      ldap.SASLBindInProgress,
			SASLCreds: nonNil(reply),
		}
	}
	return s.gssIdentity(req.GSS)
}

// gssIdentity turns a verified principal into the DN the
// connection binds as.
func (s *Store) gssIdentity(
	c *gss.Context,
) (Identity, ldap.Result) {
	if c.Authzid != "" {
		// Proxy authorization, refused for the same reason
		// EXTERNAL and PLAIN refuse it: slapd maps it
		// through authz-regexp and authz-to rules that
		// Olivine does not carry, and honouring the request
		// without the rules would grant more than asked.
		return Identity{}, ldap.Result{
			Code: ldap.UnwillingToPerform,
			Diagnostic: "proxy authorization not " +
				"supported",
		}
	}
	raw := saslDN(c.Principal, s.gss.Realm())
	norm, pretty, err := s.normalise(raw)
	if err != nil {
		return Identity{}, ldap.Result{
			Code:       ldap.InvalidCredentials,
			Diagnostic: "principal is not a usable DN",
		}
	}
	return Identity{DN: norm, Pretty: pretty},
		ldap.Result{Code: ldap.Success}
}

// saslDN builds the synthetic DN a SASL identity binds as.
//
// slapd's slap_sasl_getdn (sasl.c:1957-2010) composes it from
// the authentication identity, the realm, the mechanism and the
// literal "auth":
//
//	uid=<user>,cn=<realm>,cn=<mech>,cn=auth
//
// The realm RDN is omitted when the realm is the server's own,
// which is observed rather than derived: upstream's ldapwhoami
// binding as tester@OLIVINE.TEST against a slapd in that realm
// reported dn:uid=tester,cn=gssapi,cn=auth. Cyrus passes the
// realm through only when it differs, and slapd adds the RDN
// only when Cyrus passes it.
//
// Nothing needs to exist at this DN. It is a name for access
// control to match — `by dn.exact="uid=...,cn=auth"` — exactly
// as rootdn is a name with no entry.
func saslDN(principal, ownRealm string) string {
	user, realm := splitPrincipal(principal)
	out := "uid=" + escapeRDN(user)
	if realm != "" && !strings.EqualFold(realm, ownRealm) {
		out += ",cn=" + escapeRDN(realm)
	}
	return out + ",cn=" + strings.ToLower(MechGSSAPI) +
		",cn=auth"
}

// splitPrincipal separates user@REALM at the last @.
//
// The last, because a principal's name component may itself
// contain an escaped @ while the realm separator is the final
// one.
func splitPrincipal(p string) (user, realm string) {
	at := strings.LastIndex(p, "@")
	if at < 0 {
		return p, ""
	}
	return p[:at], p[at+1:]
}

// escapeRDN escapes an attribute value for a DN string.
//
// A Kerberos principal can hold characters that mean something
// in a DN — a comma or a plus in a name component is unusual but
// legal — and slapd escapes them for the same reason
// (ITS#3419, noted at sasl.c:1959).
func escapeRDN(v string) string {
	const special = `,+"\<>;=`
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if strings.IndexByte(special, v[i]) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

// gssFailure maps a mechanism failure to a result code.
//
// A credential that did not verify is invalidCredentials; a token
// that could not be read at all is protocolError, because the
// client has sent something that is not the mechanism.
func gssFailure(err error) ldap.Result {
	if errors.Is(err, gss.ErrAuth) {
		return ldap.Result{
			Code:       ldap.InvalidCredentials,
			Diagnostic: err.Error(),
		}
	}
	return ldap.Result{
		Code:       ldap.ProtocolError,
		Diagnostic: err.Error(),
	}
}

// nonNil keeps an empty reply distinguishable from no reply:
// Result.SASLCreds being non-nil is what sends the field.
func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
