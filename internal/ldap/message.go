package ldap

import (
	"errors"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
)

var (
	ErrNotMessage  = errors.New("ldap: not an LDAPMessage")
	ErrBadMsgID    = errors.New("ldap: malformed message id")
	ErrNoOperation = errors.New("ldap: message has no operation")
	ErrBadControls = errors.New("ldap: malformed controls")

	// ErrUnexpectedPDU is upstream's "unexpected data in
	// PDU": get_ctrls2 in controls.c:817-823 sets
	// SLAPD_DISCONNECT for it, so the connection is dropped
	// after a protocolError rather than the operation merely
	// failing.
	ErrUnexpectedPDU = errors.New("ldap: unexpected data in PDU")
)

// Message is one decoded LDAPMessage envelope. Op holds the
// operation's tag and Body its undecoded contents; the
// per-operation decoders in this package take Body.
type Message struct {
	ID       int32
	Op       ber.Tag
	Body     []byte
	Controls []Control
}

// Control is one request or response control.
type Control struct {
	OID      string
	Critical bool
	Value    []byte
	// HasValue distinguishes an absent controlValue from an
	// empty one, which RFC 4511 4.1.11 treats as different.
	HasValue bool
}

// ParseMessage decodes one complete LDAPMessage.
//
// The order of checks follows connection.c:1604-1618: the
// message id is read first and must be a universal INTEGER
// (LDAP_TAG_MSGID is 0x02), then the operation tag is peeked.
// A message whose envelope parses but whose id is the wrong
// tag is a protocol error, not a bad operation.
func ParseMessage(packet []byte) (*Message, error) {
	tag, content, err := ber.NewDecoder(packet).Next()
	if err != nil {
		return nil, err
	}
	if tag != TagMessage {
		return nil, ErrNotMessage
	}
	d := ber.NewDecoder(content)

	idTag, idBytes, err := d.Next()
	if err != nil {
		return nil, err
	}
	if idTag != TagMsgID {
		return nil, ErrBadMsgID
	}
	id, err := ber.Int32(idBytes)
	if err != nil {
		return nil, ErrBadMsgID
	}

	opTag, body, err := d.Next()
	if err != nil {
		return nil, ErrNoOperation
	}
	m := &Message{ID: id, Op: opTag, Body: body}
	return m, m.parseControls(d)
}

// parseControls reads the optional controls that follow the
// operation. The tag is context 0, constructed (0xa0).
//
// get_ctrls2 (controls.c:817-823) draws a line here that is
// easy to miss, and being stricter than it is a divergence:
//
//	if (( tag = ber_peek_tag( ber, &len )) != ctag ) {
//		if( tag == LBER_ERROR ) {
//			rs->sr_err = SLAPD_DISCONNECT;
//			rs->sr_text = "unexpected data in PDU";
//		}
//		goto return_results;
//	}
//
// Only a trailing element that will not *parse* disconnects.
// One that parses but is not 0xa0 reaches return_results with
// sr_err untouched — zero, which is LDAP_SUCCESS — so it is
// ignored and the operation proceeds.
func (m *Message) parseControls(d *ber.Decoder) error {
	if d.Done() {
		return nil
	}
	tag, content, err := d.Next()
	if err != nil {
		return ErrUnexpectedPDU
	}
	if tag != TagControls {
		return nil
	}
	cs, err := parseControlList(content)
	if err != nil {
		return err
	}
	m.Controls = cs
	return nil
}
