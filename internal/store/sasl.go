package store

import (
	"github.com/FatmanUK/olivine_ldap/internal/ldap"
)

// SASL mechanism names Olivine implements.
//
// EXTERNAL takes the identity from the transport, which under TLS
// means the client certificate. PLAIN carries a DN and password in
// the credential, and is only safe because the transport is always
// encrypted here — RFC 4616 2 requires exactly that.
//
// GSSAPI is Kerberos 5, and is advertised only when a keytab is
// configured — see Store.Mechanisms.
const (
	MechExternal = "EXTERNAL"
	MechPlain    = "PLAIN"
	MechGSSAPI   = "GSSAPI"
)

// SASLMechanisms are the ones that need no configuration.
//
// slapd hands the TLS strength and the peer certificate to its
// SASL layer the moment the handshake completes
// (connection.c:1400-1419), so SASL over TLS is the intended
// pairing rather than a conflict — the whole of this list works
// over ldaps, and so does GSSAPI.
var SASLMechanisms = []string{
	MechExternal,
	MechPlain,
}

// Mechanisms are what this server will accept, which is what the
// root DSE advertises.
//
// GSSAPI appears only when a keytab is configured. slapd
// advertises it whenever Cyrus has the plugin, keytab or not,
// which means a client can select a mechanism that cannot
// possibly succeed; advertising only what is configured is a
// deliberate divergence and the more useful answer.
func (s *Store) Mechanisms() []string {
	out := append([]string(nil), SASLMechanisms...)
	if s.gss != nil {
		out = append(out, MechGSSAPI)
	}
	return out
}

// saslBind dispatches a SASL bind.
//
// Any mechanism not implemented is refused by name, which is more
// use to whoever is debugging than a bare failure. slapd answers
// authMethodNotSupported with "requested SASL mechanism not
// supported" (sasl.c:1769-1771).
func (s *Store) saslBind(
	req *ldap.BindRequest, who Identity,
) (Identity, ldap.Result) {
	switch req.Mechanism {
	case MechExternal:
		return s.bindExternal(req)
	case MechPlain:
		return s.bindPlain(req, who)
	case MechGSSAPI:
		return s.bindGSSAPI(req)
	}
	return Identity{}, ldap.Result{
		Code: ldap.AuthMethodNotSupported,
		Diagnostic: "requested SASL mechanism not " +
			"supported: " + req.Mechanism,
	}
}

// bindExternal authenticates from the transport.
//
// Follows slapd's built-in EXTERNAL (sasl.c:1753-1766), which is
// the whole mechanism in three branches:
//
//   - a *non-empty* credential means a proxy authorization
//     identity, which is refused with unwillingToPerform "proxy
//     authorization not supported". Non-empty, not present:
//     sasl.c:1756 tests orb_cred.bv_len, and upstream's own
//     ldapwhoami sends the field present and empty on its second
//     round. Refusing on presence makes a real client fail;
//   - otherwise the bound DN *is* the transport's identity;
//   - and with no transport identity there is nothing to bind as.
//
// The last case slapd leaves as an empty DN, which is an anonymous
// success. Olivine answers invalidCredentials instead: a client
// that asked to authenticate by certificate and presented none has
// not authenticated, and reporting success would tell it otherwise.
func (s *Store) bindExternal(
	req *ldap.BindRequest,
) (Identity, ldap.Result) {
	if len(req.Credentials) > 0 {
		return Identity{}, ldap.Result{
			Code: ldap.UnwillingToPerform,
			Diagnostic: "proxy authorization not " +
				"supported",
		}
	}
	if req.External == "" {
		return Identity{}, ldap.Result{
			Code: ldap.InvalidCredentials,
			Diagnostic: "no client certificate was " +
				"presented",
		}
	}
	norm, _, err := s.normalise(req.External)
	if err != nil {
		return Identity{}, ldap.Result{
			Code: ldap.InvalidCredentials,
			Diagnostic: "the certificate subject " +
				"is not a usable DN",
		}
	}
	return Identity{DN: norm},
		ldap.Result{Code: ldap.Success}
}
