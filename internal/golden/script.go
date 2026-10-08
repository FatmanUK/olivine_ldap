package golden

import (
	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// Request is one operation to send, described so that the same
// bytes reach both implementations. Comparing two servers that
// were sent different requests proves nothing, so the script
// holds the encoded body rather than a recipe for building it.
type Request struct {
	// Name labels the step in the transcript.
	Name string
	Op   ber.Tag
	Body []byte
	// Controls are encoded after the operation.
	Controls []ldap.Control
	// NoReply marks operations that draw no response, so the
	// driver does not sit waiting for one. RFC 4511 4.3 and
	// 4.11: unbind and abandon.
	NoReply bool
}

// Script is a named sequence of requests.
type Script struct {
	Name     string
	Requests []Request
	// Pending explains why the two are expected to differ,
	// and is empty for a script that must match.
	//
	// A pending script still runs against both: the harness
	// reports the difference without failing, and complains
	// if the two *do* match, since that means the marker is
	// stale and the gap has closed.
	Pending string
}

// Encode builds the complete LDAPMessage for r at id.
func (r Request) Encode(id int32) ([]byte, error) {
	e := ber.NewEncoder()
	e.Begin(ldap.TagMessage)
	e.Int32(ldap.TagMsgID, id)
	e.Raw(r.Op, r.Body)
	encodeControls(e, r.Controls)
	e.End()
	return e.Bytes()
}

// encodeControls writes the optional control list.
func encodeControls(e *ber.Encoder, cs []ldap.Control) {
	if len(cs) == 0 {
		return
	}
	e.Begin(ldap.TagControls)
	for _, c := range cs {
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
