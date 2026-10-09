package server

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"net"
	"strings"
)

// peerDN returns the client certificate's subject as an LDAP DN,
// or the empty string when the client presented none.
//
// This is what slapd does on completing the handshake:
// connection.c:1405 calls dnX509peerNormalize, which converts the
// peer certificate's subject, and hands the result to the SASL
// layer as the EXTERNAL identity.
//
// The ordering is the part worth stating. An X.509 subject reads
// most-general-first — C, then O, then CN — and an LDAP DN reads
// most-specific-first, so the sequence reverses. Go's
// pkix.Name.String() already emits RFC 2253 order, which is the
// LDAP one; writing the RDNs out in certificate order gives a DN
// that looks right and names nothing.
func peerDN(conn net.Conn) string {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return ""
	}
	chains := tc.ConnectionState().PeerCertificates
	if len(chains) == 0 {
		return ""
	}
	return subjectDN(chains[0].Subject)
}

// subjectDN renders a certificate subject as an LDAP DN.
func subjectDN(name pkix.Name) string {
	dn := name.String()
	if strings.TrimSpace(dn) == "" {
		return ""
	}
	return dn
}
