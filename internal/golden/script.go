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

// BindRequestBody encodes a simple bind, so a script can
// authenticate before the operations that need it.
//
// Both implementations are given the same administrator, which
// slapd calls rootdn: an identity with no entry that bypasses
// access control. Without it an update cannot be compared at all,
// since an anonymous one is refused before the ACLs are reached.
func BindRequestBody(name, password string) []byte {
	e := ber.NewEncoder()
	e.Int32(ber.TagInteger, ldap.Version3)
	e.String(ldap.TagLDAPDN, name)
	e.String(ldap.AuthSimple, password)
	out, err := e.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}

// AdminBind is a request that binds as the shared administrator.
func AdminBind() Request {
	return Request{
		Name: "bind as admin",
		Op:   ldap.ReqBind,
		Body: BindRequestBody(rootDN, rootPW),
	}
}

// Script is a named sequence of requests.
type Script struct {
	Name     string
	Requests []Request
	// ResultsOnly compares the result codes and the number of
	// entries, but not which entries came back.
	//
	// For a size-limited search that is the only honest
	// comparison: nothing in RFC 4511 says *which* entries a
	// truncated search returns, and the two servers truncate in
	// their own traversal orders — slapd in index order,
	// Olivine ordered by DN. Comparing the sets would assert
	// something neither implementation promises.
	ResultsOnly bool
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
