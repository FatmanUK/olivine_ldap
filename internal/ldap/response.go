package ldap

import "github.com/FatmanUK/openldap_olivine/internal/ber"

// Result is the LDAPResult every operation closes with.
type Result struct {
	Code       ResultCode
	MatchedDN  string
	Diagnostic string
	Referral   []string
}

// EncodeResultWithControls builds a result message carrying
// response controls.
//
// Controls follow the protocol operation under the same context 0
// constructed tag a request uses, so a client decodes them the
// same way. A response with no controls omits the element
// entirely rather than sending an empty sequence, which is what
// slapd does and what EncodeResult below is for.
func EncodeResultWithControls(
	id int32, resTag ber.Tag, r Result,
	controls []Control,
) ([]byte, error) {
	e := ber.NewEncoder()
	e.Begin(TagMessage)
	e.Int32(TagMsgID, id)
	e.Begin(resTag)
	writeResultFields(e, r)
	e.End()
	writeControls(e, controls)
	e.End()
	return e.Bytes()
}

// writeControls writes a control list, or nothing when empty.
func writeControls(e *ber.Encoder, controls []Control) {
	if len(controls) == 0 {
		return
	}
	e.Begin(TagControls)
	for _, c := range controls {
		e.Begin(ber.TagSequence)
		e.String(ber.TagOctetString, c.OID)
		if c.Critical {
			e.Bool(ber.TagBoolean, true)
		}
		if c.HasValue {
			e.OctetString(ber.TagOctetString, c.Value)
		}
		e.End()
	}
	e.End()
}

// EncodeResult builds a complete LDAPMessage carrying one
// LDAPResult under the response tag resTag.
//
//	LDAPResult ::= SEQUENCE {
//		resultCode      ENUMERATED { ... },
//		matchedDN       LDAPDN,
//		diagnosticMessage LDAPString,
//		referral        [3] Referral OPTIONAL }
func EncodeResult(
	id int32, resTag ber.Tag, r Result,
) ([]byte, error) {
	return EncodeResultWithControls(id, resTag, r, nil)
}

// writeResultFields writes the four LDAPResult components.
func writeResultFields(e *ber.Encoder, r Result) {
	e.Enum(ber.TagEnumerated, int32(r.Code))
	e.String(TagLDAPDN, r.MatchedDN)
	e.String(ber.TagOctetString, r.Diagnostic)
	if len(r.Referral) == 0 {
		return
	}
	e.Begin(TagReferral)
	for _, u := range r.Referral {
		e.String(ber.TagOctetString, u)
	}
	e.End()
}

// EncodeNotice builds an unsolicited notice of disconnection:
// an ExtendedResponse with message id 0, as RFC 4511 4.4.1
// requires and as send_ldap_disconnect does for LDAPv3
// (result.c: sr_tag = LDAP_RES_EXTENDED, sr_msgid =
// LDAP_RES_UNSOLICITED, which is 0). This is why a protocol
// error reaches the client as a diagnostic rather than a bare
// TCP reset.
//
// Only three codes may be sent this way. result.c asserts it:
//
//	#define LDAP_UNSOLICITED_ERROR(e) \
//		(  (e) == LDAP_PROTOCOL_ERROR \
//		|| (e) == LDAP_STRONG_AUTH_REQUIRED \
//		|| (e) == LDAP_UNAVAILABLE )
//
// CanBeUnsolicited reports the same, so a caller can check
// rather than trip the equivalent assertion.
func EncodeNotice(r Result) ([]byte, error) {
	e := ber.NewEncoder()
	e.Begin(TagMessage)
	e.Int32(TagMsgID, 0)
	e.Begin(ResExtended)
	writeResultFields(e, r)
	e.String(TagExopResOID, OIDNoticeOfDisconnection)
	e.End()
	e.End()
	return e.Bytes()
}

// CanBeUnsolicited reports whether c may be sent as an
// unsolicited notice. See the assertion quoted on
// EncodeNotice.
func CanBeUnsolicited(c ResultCode) bool {
	return c == ProtocolError ||
		c == StrongerAuthRequired || c == Unavailable
}

// OIDNoticeOfDisconnection is the responseName on an
// unsolicited notice of disconnection, RFC 4511 4.4.1, and
// ldap.h:408.
const OIDNoticeOfDisconnection = "1.3.6.1.4.1.1466.20036"

// OIDStartTLS is recognised only to be refused: Olivine is
// TLS-only, so starttls.c is not ported. See BOOTSTRAP.md
// 3.3, and ldap.h:412.
const OIDStartTLS = "1.3.6.1.4.1.1466.20037"

// EncodeBindResponse builds a BindResponse, optionally carrying
// serverSaslCreds.
//
//	BindResponse ::= [APPLICATION 1] SEQUENCE {
//		COMPONENTS OF LDAPResult,
//		serverSaslCreds [7] OCTET STRING OPTIONAL }
//
// The credentials are the server's half of a multi-step SASL
// exchange. A mechanism that completes in one step — EXTERNAL —
// sends none, and the field is omitted rather than sent empty.
func EncodeBindResponse(
	id int32, r Result, saslCreds []byte, has bool,
) ([]byte, error) {
	e := ber.NewEncoder()
	e.Begin(TagMessage)
	e.Int32(TagMsgID, id)
	e.Begin(ResBind)
	writeResultFields(e, r)
	if has {
		e.OctetString(TagSASLResCreds, saslCreds)
	}
	e.End()
	e.End()
	return e.Bytes()
}
