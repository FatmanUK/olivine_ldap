package ldap

import (
	"errors"
	"testing"

	"github.com/FatmanUK/olivine_ldap/internal/ber"
)

// envelope builds an LDAPMessage around one operation.
func envelope(id int32, op ber.Tag, body []byte) []byte {
	e := ber.NewEncoder()
	e.Begin(TagMessage)
	e.Int32(TagMsgID, id)
	e.Raw(op, body)
	e.End()
	out, err := e.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}

func TestParseMessage(t *testing.T) {
	packet := envelope(7, ReqUnbind, nil)
	m, err := ParseMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 7 {
		t.Errorf("id = %d, want 7", m.ID)
	}
	if m.Op != ReqUnbind {
		t.Errorf("op = %#x, want %#x", m.Op, ReqUnbind)
	}
	if len(m.Controls) != 0 {
		t.Errorf("controls = %d, want 0", len(m.Controls))
	}
}

func TestParseMessageRejects(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		err  error
	}{
		{"not a sequence",
			[]byte{0x04, 0x01, 0x00}, ErrNotMessage},
		{"empty", []byte{}, ber.ErrTruncated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseMessage(c.in)
			if !errors.Is(err, c.err) {
				t.Fatalf("err = %v, want %v",
					err, c.err)
			}
		})
	}
}

func TestParseMessageMsgIDMustBeInteger(t *testing.T) {
	// connection.c:1604 requires ber_get_int to return
	// LDAP_TAG_MSGID (0x02); an octet string there is not a
	// message id.
	e := ber.NewEncoder()
	e.Begin(TagMessage)
	e.String(ber.TagOctetString, "7")
	e.Raw(ReqUnbind, nil)
	e.End()
	packet, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMessage(packet); !errors.Is(
		err, ErrBadMsgID) {
		t.Fatalf("err = %v, want ErrBadMsgID", err)
	}
}

func TestParseMessageNoOperation(t *testing.T) {
	e := ber.NewEncoder()
	e.Begin(TagMessage)
	e.Int32(TagMsgID, 1)
	e.End()
	packet, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMessage(packet); !errors.Is(
		err, ErrNoOperation) {
		t.Fatalf("err = %v, want ErrNoOperation", err)
	}
}

// Upstream ignores a well-formed trailing element that is not
// the controls tag: get_ctrls2 falls through to
// return_results with sr_err still LDAP_SUCCESS. Being
// stricter would be a divergence.
func TestTrailingNonControlsIsIgnored(t *testing.T) {
	e := ber.NewEncoder()
	e.Begin(TagMessage)
	e.Int32(TagMsgID, 3)
	e.Raw(ReqUnbind, nil)
	e.String(ber.TagOctetString, "junk")
	e.End()
	packet, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseMessage(packet)
	if err != nil {
		t.Fatalf("should be ignored, got %v", err)
	}
	if len(m.Controls) != 0 {
		t.Errorf("controls = %d, want 0", len(m.Controls))
	}
}

// A trailing element that will not parse is a different case:
// "unexpected data in PDU", and the connection is dropped.
func TestTrailingGarbageIsUnexpectedPDU(t *testing.T) {
	packet := envelope(3, ReqUnbind, nil)
	// 0x82 promises two length octets and supplies none.
	packet = append(packet, 0x30, 0x82)
	// Widen the envelope to cover the appended octets.
	packet[1] += 2
	_, err := ParseMessage(packet)
	if !errors.Is(err, ErrUnexpectedPDU) {
		t.Fatalf("err = %v, want ErrUnexpectedPDU", err)
	}
}

func TestIsRequest(t *testing.T) {
	// The accepted set is connection.c:1080-1089.
	for _, tag := range []ber.Tag{
		ReqBind, ReqUnbind, ReqAdd, ReqDelete, ReqModDN,
		ReqModify, ReqCompare, ReqSearch, ReqAbandon,
		ReqExtended,
	} {
		if !IsRequest(tag) {
			t.Errorf("%#x should be a request", tag)
		}
	}
	for _, tag := range []ber.Tag{
		ResBind, ResSearchEntry, 0x00, 0x30,
	} {
		if IsRequest(tag) {
			t.Errorf("%#x should not be a request", tag)
		}
	}
}
