package ber

import "errors"

// Tag is a BER tag in the packed representation the C uses:
// the raw tag octets shifted into one integer, not a decoded
// class/number pair.
//
// This is deliberate. include/ldap.h:522-548 expresses every
// LDAP operation as a packed constant — LDAP_REQ_BIND is
// 0x60, LDAP_RES_EXTENDED is 0x78 — so a decoded form would
// have to be re-packed at every comparison. ber_tag_t is
// unsigned long, and ber_tag_and_rest in liblber/decode.c
// packs up to 8 octets into it.
type Tag uint64

// Tag classes and the constructed bit, from lber.h:60-72.
const (
	ClassUniversal   Tag = 0x00
	ClassApplication Tag = 0x40
	ClassContext     Tag = 0x80
	ClassPrivate     Tag = 0xc0
	ClassMask        Tag = 0xc0

	Primitive   Tag = 0x00
	Constructed Tag = 0x20

	bigTagMask  Tag = 0x1f
	moreTagMask Tag = 0x80
)

// Universal tags that LDAP uses.
const (
	TagBoolean     Tag = 0x01
	TagInteger     Tag = 0x02
	TagBitString   Tag = 0x03
	TagOctetString Tag = 0x04
	TagNull        Tag = 0x05
	TagOID         Tag = 0x06
	TagEnumerated  Tag = 0x0a
	TagSequence    Tag = 0x30
	TagSet         Tag = 0x31
)

// Incoming message size limits, from slapd/slap.h:142-143.
// The limit doubles-and-then-some once a connection has
// authenticated, which is why there are two.
const (
	MaxIncomingDefault = (1 << 18) - 1
	MaxIncomingAuth    = (1 << 24) - 1
)

// maxIntLen is the longest integer contents accepted.
// ber_decode_int rejects len > sizeof(ber_int_t)
// (liblber/decode.c), and configure resolves LBER_INT_T to
// int on any platform whose int is at least 32 bits — see
// configure:25130-25140. So this is 4, not 8, and a 5-octet
// integer is a parse error however well it would fit in an
// int64.
const maxIntLen = 4

// The C collapses every decode failure into LBER_DEFAULT,
// ((ber_tag_t) -1). Distinct errors are an improvement, but
// what must match upstream is which inputs are *rejected*,
// not how the rejection is spelled.
var (
	ErrTruncated   = errors.New("ber: truncated element")
	ErrIndefinite  = errors.New("ber: indefinite length")
	ErrLengthRange = errors.New("ber: length out of range")
	ErrTagTooLong  = errors.New("ber: tag too long")
	ErrIntRange    = errors.New("ber: integer too long")
	ErrBadBool     = errors.New("ber: malformed boolean")
	ErrTooLarge    = errors.New("ber: message exceeds limit")
	ErrEmpty       = errors.New("ber: zero-length message")
	ErrUnbalanced  = errors.New("ber: unbalanced constructed")
)

// Class returns the tag's class bits.
func (t Tag) Class() Tag {
	return t.firstOctet() & ClassMask
}

// IsConstructed reports whether the constructed bit is set.
func (t Tag) IsConstructed() bool {
	return t.firstOctet()&Constructed != 0
}

// firstOctet returns the leading octet of a packed tag.
func (t Tag) firstOctet() Tag {
	for t > 0xff {
		t >>= 8
	}
	return t
}
