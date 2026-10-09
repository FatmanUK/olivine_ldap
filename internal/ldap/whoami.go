package ldap

import "github.com/FatmanUK/openldap_olivine/internal/ber"

// OIDWhoAmI is the "Who am I?" extended operation, RFC 4532 and
// ldap.h:435.
const OIDWhoAmI = "1.3.6.1.4.1.4203.1.11.3"

// WhoAmIValue renders the authzId a whoami response carries.
//
// RFC 4532 2.2: a bound identity is the dnAuthzId form,
// "dn:" followed by the DN, and an *empty* value means anonymous
// — which is why upstream's ldapwhoami prints "anonymous" rather
// than an error when nothing has bound.
func WhoAmIValue(who Identity) (string, bool) {
	if who.Pretty != "" {
		return "dn:" + who.Pretty, true
	}
	if who.DN != "" {
		return "dn:" + who.DN, true
	}
	return "", false
}

// EncodeExtendedResponse builds an ExtendedResponse.
//
//	ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
//		COMPONENTS OF LDAPResult,
//		responseName  [10] LDAPOID OPTIONAL,
//		responseValue [11] OCTET STRING OPTIONAL }
//
// slapd omits responseName on a whoami reply, so this does too: a
// client matched the request to the reply by message id already.
func EncodeExtendedResponse(
	id int32, r Result, value string, hasValue bool,
) ([]byte, error) {
	e := ber.NewEncoder()
	e.Begin(TagMessage)
	e.Int32(TagMsgID, id)
	e.Begin(ResExtended)
	writeResultFields(e, r)
	if hasValue {
		e.String(TagExopResValue, value)
	}
	e.End()
	e.End()
	return e.Bytes()
}
