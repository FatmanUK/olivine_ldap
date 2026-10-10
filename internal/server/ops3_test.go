package server

import (
	"testing"

	"github.com/FatmanUK/olivine_ldap/internal/ber"
	"github.com/FatmanUK/olivine_ldap/internal/ldap"
)

// A bind with a version other than 3 is protocolError: Olivine
// serves LDAPv3 only (RFC 4511 4.2).
func TestBindRejectsOldVersion(t *testing.T) {
	fake := newFake()
	_, cliTLS, addr := startWith(t, fake)
	c := dial(t, cliTLS, addr)

	e := ber.NewEncoder()
	e.Int32(ber.TagInteger, 2)
	e.String(ldap.TagLDAPDN, "cn=admin,dc=example,dc=com")
	e.String(ldap.AuthSimple, "secret")
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(
		envelope(t, 1, ldap.ReqBind, body)); err != nil {
		t.Fatal(err)
	}
	m := readMessage(t, c)
	if code := resultCode(t, m); code !=
		ldap.ProtocolError {
		t.Errorf("code = %v, want protocolError", code)
	}
	// The backend must not have been consulted at all.
	if len(fake.bindCalls) != 0 {
		t.Errorf("backend saw %d binds", len(fake.bindCalls))
	}
}

func TestBindReachesBackend(t *testing.T) {
	fake := newFake()
	_, cliTLS, addr := startWith(t, fake)
	c := dial(t, cliTLS, addr)

	e := ber.NewEncoder()
	e.Int32(ber.TagInteger, 3)
	e.String(ldap.TagLDAPDN, "cn=admin,dc=example,dc=com")
	e.String(ldap.AuthSimple, "secret")
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(
		envelope(t, 1, ldap.ReqBind, body)); err != nil {
		t.Fatal(err)
	}
	m := readMessage(t, c)
	if m.Op != ldap.ResBind {
		t.Errorf("op = %#x, want %#x", m.Op, ldap.ResBind)
	}
	if len(fake.bindCalls) != 1 {
		t.Fatalf("%d bind calls", len(fake.bindCalls))
	}
	if fake.bindCalls[0].Simple != "secret" {
		t.Errorf("password not passed through")
	}
}

// A DelRequest's body is the DN alone, not wrapped in a
// sequence: RFC 4511 4.8 makes it [APPLICATION 10] LDAPDN,
// which is why the tag is primitive.
func TestDeletePassesBareDN(t *testing.T) {
	fake := newFake()
	_, cliTLS, addr := startWith(t, fake)
	c := dial(t, cliTLS, addr)

	e := ber.NewEncoder()
	e.Begin(ldap.TagMessage)
	e.Int32(ldap.TagMsgID, 4)
	e.OctetString(ldap.ReqDelete,
		[]byte("cn=x,dc=example,dc=com"))
	e.End()
	packet, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(packet); err != nil {
		t.Fatal(err)
	}
	m := readMessage(t, c)
	if m.Op != ldap.ResDelete {
		t.Errorf("op = %#x, want %#x", m.Op, ldap.ResDelete)
	}
	if len(fake.deleteCalls) != 1 {
		t.Fatalf("%d delete calls", len(fake.deleteCalls))
	}
	if fake.deleteCalls[0] != "cn=x,dc=example,dc=com" {
		t.Errorf("dn = %q", fake.deleteCalls[0])
	}
}

func TestCompareReachesBackend(t *testing.T) {
	fake := newFake()
	fake.result = ldap.Result{Code: ldap.CompareTrue}
	_, cliTLS, addr := startWith(t, fake)
	c := dial(t, cliTLS, addr)

	e := ber.NewEncoder()
	e.String(ldap.TagLDAPDN, "cn=x,dc=example,dc=com")
	e.Begin(ber.TagSequence)
	e.String(ber.TagOctetString, "cn")
	e.String(ber.TagOctetString, "x")
	e.End()
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(
		envelope(t, 6, ldap.ReqCompare, body)); err != nil {
		t.Fatal(err)
	}
	m := readMessage(t, c)
	if code := resultCode(t, m); code != ldap.CompareTrue {
		t.Errorf("code = %v, want compareTrue", code)
	}
	if len(fake.compareCalls) != 1 {
		t.Fatalf("%d compare calls",
			len(fake.compareCalls))
	}
	if fake.compareCalls[0].Attribute != "cn" {
		t.Errorf("attribute = %q",
			fake.compareCalls[0].Attribute)
	}
}

// The connection records the DN the *backend* reports, not the
// one the client sent. A client may spell its DN however it
// likes, and an unnormalised DN compares against nothing — so
// `self` and `dn=` access clauses would silently never match.
func TestBoundDNComesFromTheBackend(t *testing.T) {
	fake := newFake()
	srv, cliTLS, addr := startWith(t, fake)
	_ = srv
	c := dial(t, cliTLS, addr)

	e := ber.NewEncoder()
	e.Int32(ber.TagInteger, 3)
	// Mixed case, as a client might send it.
	e.String(ldap.TagLDAPDN, "CN=Admin,DC=Example,DC=COM")
	e.String(ldap.AuthSimple, "secret")
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(
		envelope(t, 1, ldap.ReqBind, body)); err != nil {
		t.Fatal(err)
	}
	if m := readMessage(t, c); m.Op != ldap.ResBind {
		t.Fatalf("op = %#x", m.Op)
	}
	// A second operation carries the identity, which must be
	// the fake's lower-cased answer rather than the client's
	// spelling.
	if _, err := c.Write(envelope(
		t, 2, ldap.ReqSearch, searchBody(t))); err != nil {
		t.Fatal(err)
	}
	readMessage(t, c)
	last := fake.identities[len(fake.identities)-1]
	if last.DN != "cn=admin,dc=example,dc=com" {
		t.Errorf("identity = %q, want the backend's "+
			"normalised DN", last.DN)
	}
}

// At bind time the identity passed down is the one *before* the
// bind — anonymous on a fresh connection. That is what makes the
// `by self write by users read by * none` policy unbindable.
func TestBindSeesThePreviousIdentity(t *testing.T) {
	fake := newFake()
	_, cliTLS, addr := startWith(t, fake)
	c := dial(t, cliTLS, addr)

	e := ber.NewEncoder()
	e.Int32(ber.TagInteger, 3)
	e.String(ldap.TagLDAPDN, "cn=admin,dc=example,dc=com")
	e.String(ldap.AuthSimple, "secret")
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(
		envelope(t, 1, ldap.ReqBind, body)); err != nil {
		t.Fatal(err)
	}
	readMessage(t, c)
	if len(fake.identities) == 0 {
		t.Fatal("no identity recorded")
	}
	if !fake.identities[0].Anonymous() {
		t.Errorf("bind saw %q, want anonymous",
			fake.identities[0].DN)
	}
}
