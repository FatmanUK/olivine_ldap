// Package gss implements the acceptor side of the Kerberos 5
// GSS-API mechanism, as much of it as a SASL GSSAPI bind needs.
//
// There is no C to port here: slapd delegates the whole
// mechanism to Cyrus SASL, which delegates it to MIT Kerberos.
// What is ported is the *observable exchange*, captured from
// upstream's own ldapwhoami talking to slapd through a logging
// proxy, and that exchange is three LDAP bind round trips:
//
//  1. the client sends an RFC 2743 3.1 initial context token
//     wrapping a Kerberos AP-REQ; the acceptor answers with one
//     wrapping an AP-REP, and saslBindInProgress.
//  2. the client sends a bind with *no credentials field at
//     all* — not an empty one; the acceptor answers with an RFC
//     4121 4.2.6.2 Wrap token carrying the security-layer
//     bitmask and maximum buffer size.
//  3. the client sends a Wrap token naming the layer it chose
//     and, optionally, an authorization identity; the acceptor
//     answers success with no credentials.
//
// Only the no-security-layer option is offered. slapd offers
// integrity and confidentiality too and MIT takes them by
// default, which over TLS means a second layer of encryption
// inside the first; Olivine is TLS-only, so there is nothing for
// a SASL security layer to protect that is not protected
// already. This is a deliberate divergence, and it is visible to
// a client only as `SASL SSF: 0`.
package gss
