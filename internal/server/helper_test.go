package server

import (
	"io"
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// envelope wraps an operation in an LDAPMessage.
func envelope(
	t *testing.T, id int32, op ber.Tag, body []byte,
) []byte {
	t.Helper()
	e := ber.NewEncoder()
	e.Begin(ldap.TagMessage)
	e.Int32(ldap.TagMsgID, id)
	e.Raw(op, body)
	e.End()
	out, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// searchBody builds a minimal well-formed SearchRequest, so a
// test exercises the dispatcher rather than the parser.
func searchBody(t *testing.T) []byte {
	t.Helper()
	e := ber.NewEncoder()
	e.String(ldap.TagLDAPDN, "dc=example,dc=com")
	e.Enum(ber.TagEnumerated, int32(ldap.ScopeBase))
	e.Enum(ber.TagEnumerated, 0)
	e.Int32(ber.TagInteger, 0)
	e.Int32(ber.TagInteger, 0)
	e.Bool(ber.TagBoolean, false)
	e.String(0x87, "objectClass")
	e.Begin(ber.TagSequence)
	e.End()
	out, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// readMessage reads one LDAPMessage from r.
func readMessage(t *testing.T, r io.Reader) *ldap.Message {
	t.Helper()
	packet, err := ber.ReadPacket(r, ber.MaxIncomingAuth)
	if err != nil {
		t.Fatalf("reading reply: %v", err)
	}
	m, err := ldap.ParseMessage(packet)
	if err != nil {
		t.Fatalf("parsing reply: %v", err)
	}
	return m
}

// resultCode pulls the resultCode out of a response body.
func resultCode(
	t *testing.T, m *ldap.Message,
) ldap.ResultCode {
	t.Helper()
	_, content, err := ber.NewDecoder(m.Body).Next()
	if err != nil {
		t.Fatalf("result code: %v", err)
	}
	n, err := ber.Enum(content)
	if err != nil {
		t.Fatalf("result code: %v", err)
	}
	return ldap.ResultCode(n)
}
