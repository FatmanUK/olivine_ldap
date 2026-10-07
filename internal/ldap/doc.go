// Package ldap defines the protocol messages of RFC 4511 and
// their result codes.
//
// The operation dispatch to match is connection.c:1080-1089
// in the openldap submodule.
//
// TLS-only means starttls.c is not ported, but the StartTLS
// extended operation must still be recognised and answered
// unwillingToPerform rather than met with silence or a parse
// error. Confirm the exact code and diagnostic against the C
// before implementing it.
package ldap
