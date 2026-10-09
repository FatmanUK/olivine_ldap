package ldap

import "github.com/FatmanUK/openldap_olivine/internal/ber"

// Operation tags, from include/ldap.h:522-548. These are
// packed BER tags, not ordinals: the class and constructed
// bits are part of the value.
const (
	ReqBind     ber.Tag = 0x60
	ReqUnbind   ber.Tag = 0x42
	ReqSearch   ber.Tag = 0x63
	ReqModify   ber.Tag = 0x66
	ReqAdd      ber.Tag = 0x68
	ReqDelete   ber.Tag = 0x4a
	ReqModDN    ber.Tag = 0x6c
	ReqCompare  ber.Tag = 0x6e
	ReqAbandon  ber.Tag = 0x50
	ReqExtended ber.Tag = 0x77
)

// Response tags, from include/ldap.h:536-548.
const (
	ResBind            ber.Tag = 0x61
	ResSearchEntry     ber.Tag = 0x64
	ResSearchReference ber.Tag = 0x73
	ResSearchResult    ber.Tag = 0x65
	ResModify          ber.Tag = 0x67
	ResAdd             ber.Tag = 0x69
	ResDelete          ber.Tag = 0x6b
	ResModDN           ber.Tag = 0x6d
	ResCompare         ber.Tag = 0x6f
	ResExtended        ber.Tag = 0x78
	ResIntermediate    ber.Tag = 0x79
)

// Envelope and field tags, from include/ldap.h:500-512.
const (
	TagMessage      ber.Tag = 0x30
	TagMsgID        ber.Tag = 0x02
	TagLDAPDN       ber.Tag = 0x04
	TagLDAPCred     ber.Tag = 0x04
	TagControls     ber.Tag = 0xa0
	TagReferral     ber.Tag = 0xa3
	TagNewSuperior  ber.Tag = 0x80
	TagExopReqOID   ber.Tag = 0x80
	TagExopReqValue ber.Tag = 0x81
	// TagSASLResCreds is serverSaslCreds on a bind response,
	// from ldap.h:519. It shares its value with the present
	// filter and with requestName, which is harmless: a tag
	// only has to be unambiguous within the element that
	// carries it.
	TagSASLResCreds ber.Tag = 0x87
	TagExopResOID   ber.Tag = 0x8a
	TagExopResValue ber.Tag = 0x8b
)

// Bind authentication choices, from include/ldap.h:561-562.
const (
	AuthSimple ber.Tag = 0x80
	AuthSASL   ber.Tag = 0xa3
)

// Version3 is the only protocol version Olivine serves.
const Version3 = 3

// IsRequest reports whether t is an operation Olivine
// dispatches. The set matches connection.c:1080-1089.
func IsRequest(t ber.Tag) bool {
	switch t {
	case ReqBind, ReqUnbind, ReqAdd, ReqDelete, ReqModDN,
		ReqModify, ReqCompare, ReqSearch, ReqAbandon,
		ReqExtended:
		return true
	}
	return false
}
