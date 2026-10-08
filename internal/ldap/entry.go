package ldap

import "github.com/FatmanUK/openldap_olivine/internal/ber"

// SearchEntry is one entry to send back.
type SearchEntry struct {
	DN         string
	Attributes []AttributeChange
}

// EncodeSearchEntry builds a SearchResultEntry message.
//
//	SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
//		objectName      LDAPDN,
//		attributes      PartialAttributeList }
//
// PartialAttributeList ::= SEQUENCE OF
//
//	partialAttribute PartialAttribute
//
//	PartialAttribute ::= SEQUENCE {
//		type    AttributeDescription,
//		vals    SET OF value AttributeValue }
//
// The values are a SET, not a SEQUENCE: attribute values are
// unordered, which is why the golden harness sorts them before
// comparing.
func EncodeSearchEntry(
	id int32, e SearchEntry,
) ([]byte, error) {
	enc := ber.NewEncoder()
	enc.Begin(TagMessage)
	enc.Int32(TagMsgID, id)
	enc.Begin(ResSearchEntry)
	enc.String(TagLDAPDN, e.DN)
	enc.Begin(ber.TagSequence)
	for _, a := range e.Attributes {
		writeAttribute(enc, a)
	}
	enc.End()
	enc.End()
	enc.End()
	return enc.Bytes()
}

// writeAttribute writes one PartialAttribute.
func writeAttribute(
	enc *ber.Encoder, a AttributeChange,
) {
	enc.Begin(ber.TagSequence)
	enc.String(ber.TagOctetString, a.Type)
	enc.Begin(ber.TagSet)
	for _, v := range a.Values {
		enc.String(ber.TagOctetString, v)
	}
	enc.End()
	enc.End()
}

// NoAttributes is the OID-like marker a client sends to ask for
// no attributes at all, RFC 4511 4.5.1.8.
const NoAttributes = "1.1"

// AllUserAttributes is the "*" shorthand.
const AllUserAttributes = "*"

// AllOperationalAttributes is the "+" shorthand, an OpenLDAP
// and RFC 3673 extension.
const AllOperationalAttributes = "+"
