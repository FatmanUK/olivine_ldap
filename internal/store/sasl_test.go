package store

import (
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// saslBindReq builds a SASL bind request.
func saslBindReq(
	mech string, creds []byte, hasCreds bool,
	external string,
) *ldap.BindRequest {
	return &ldap.BindRequest{
		Version:        ldap.Version3,
		IsSASL:         true,
		Mechanism:      mech,
		Credentials:    creds,
		HasCredentials: hasCreds,
		External:       external,
	}
}

// plainCred builds an RFC 4616 PLAIN credential.
func plainCred(authzid, authcid, passwd string) []byte {
	out := append([]byte(authzid), 0)
	out = append(out, []byte(authcid)...)
	out = append(out, 0)
	return append(out, []byte(passwd)...)
}

// EXTERNAL binds as the transport's identity — the client
// certificate's subject under TLS.
func TestSASLExternalBindsAsTheCertificate(t *testing.T) {
	s := testStore(t)
	seed(t, s)

	id, res := s.BackendBind(saslBindReq(
		MechExternal, nil, false,
		"cn=Alice,ou=people,dc=example,dc=com"), anyone)
	if res.Code != ldap.Success {
		t.Fatalf("code = %v, want success", res.Code)
	}
	// Normalised, so an access check can compare it.
	want := "cn=alice,ou=people,dc=example,dc=com"
	if id.DN != want {
		t.Errorf("identity = %q, want %q", id.DN, want)
	}
}

// With no client certificate there is nothing to bind as. slapd
// leaves an empty DN here, which is an anonymous success; Olivine
// answers invalidCredentials, because a client that asked to
// authenticate by certificate and presented none has not
// authenticated.
func TestSASLExternalWithoutCertificate(t *testing.T) {
	s := testStore(t)
	id, res := s.BackendBind(saslBindReq(
		MechExternal, nil, false, ""), anyone)
	if res.Code != ldap.InvalidCredentials {
		t.Errorf("code = %v, want invalidCredentials",
			res.Code)
	}
	if id.DN != "" {
		t.Errorf("identity = %q, want none", id.DN)
	}
}

// A *non-empty* credential on EXTERNAL is a proxy authorization
// identity, which slapd refuses with "proxy authorization not
// supported" (sasl.c:1756-1759).
func TestSASLExternalRefusesCredentials(t *testing.T) {
	s := testStore(t)
	_, res := s.BackendBind(saslBindReq(
		MechExternal, []byte("cn=someone"), true,
		"cn=Alice,ou=people,dc=example,dc=com"), anyone)
	if res.Code != ldap.UnwillingToPerform {
		t.Errorf("code = %v, want unwillingToPerform",
			res.Code)
	}
}

// An unimplemented mechanism is refused by name, which is more use
// than a bare failure.
// An *empty* credential is not proxy authorization. sasl.c:1756
// tests orb_cred.bv_len, and upstream's ldapwhoami sends the
// field present and empty on its second round — refusing on
// presence makes a real client fail, which is how this was found.
func TestSASLExternalAcceptsEmptyCredentials(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	_, res := s.BackendBind(saslBindReq(
		MechExternal, []byte{}, true,
		"cn=Alice,ou=people,dc=example,dc=com"), anyone)
	if res.Code != ldap.Success {
		t.Errorf("code = %v, want success", res.Code)
	}
}

func TestSASLUnknownMechanism(t *testing.T) {
	s := testStore(t)
	_, res := s.BackendBind(saslBindReq(
		"GSSAPI", nil, false, ""), anyone)
	if res.Code != ldap.AuthMethodNotSupported {
		t.Fatalf("code = %v, want authMethodNotSupported",
			res.Code)
	}
	if res.Diagnostic == "" {
		t.Error("the mechanism should be named")
	}
}

// PLAIN carries authzid NUL authcid NUL passwd (RFC 4616 2).
func TestSASLPlainBinds(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	dn := "cn=admin,dc=example,dc=com"
	withPassword(t, s, dn, "secret")

	id, res := s.BackendBind(saslBindReq(
		MechPlain, plainCred("", dn, "secret"), true,
		""), anyone)
	if res.Code != ldap.Success {
		t.Fatalf("code = %v, want success", res.Code)
	}
	if id.DN != "cn=admin,dc=example,dc=com" {
		t.Errorf("identity = %q", id.DN)
	}
}

func TestSASLPlainWrongPassword(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	dn := "cn=admin,dc=example,dc=com"
	withPassword(t, s, dn, "secret")

	_, res := s.BackendBind(saslBindReq(
		MechPlain, plainCred("", dn, "wrong"), true,
		""), anyone)
	if res.Code != ldap.InvalidCredentials {
		t.Errorf("code = %v, want invalidCredentials",
			res.Code)
	}
}

// A non-empty authzid asks to act as somebody else, which is
// proxy authorization.
func TestSASLPlainRefusesProxyAuthz(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	_, res := s.BackendBind(saslBindReq(
		MechPlain,
		plainCred("cn=other", "cn=admin,dc=example,dc=com",
			"secret"), true, ""), anyone)
	if res.Code != ldap.UnwillingToPerform {
		t.Errorf("code = %v, want unwillingToPerform",
			res.Code)
	}
}

func TestSASLPlainMalformed(t *testing.T) {
	s := testStore(t)
	for _, cred := range [][]byte{
		nil,
		[]byte("no separators"),
		[]byte("one\x00separator"),
	} {
		_, res := s.BackendBind(saslBindReq(
			MechPlain, cred, true, ""), anyone)
		if res.Code != ldap.InvalidCredentials {
			t.Errorf("%q: code = %v", cred, res.Code)
		}
	}
}

// An empty password is an unauthenticated bind by another route.
func TestSASLPlainEmptyPassword(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	_, res := s.BackendBind(saslBindReq(
		MechPlain,
		plainCred("", "cn=admin,dc=example,dc=com", ""),
		true, ""), anyone)
	if res.Code == ldap.Success {
		t.Error("an empty password must not succeed")
	}
}

// The root DSE advertises what is implemented, and nothing else.
func TestRootDSEAdvertisesSASLMechanisms(t *testing.T) {
	s := testStore(t)
	got, _, _ := s.BackendSearch(
		rootSearch("supportedSASLMechanisms"), anyone)
	if len(got) != 1 {
		t.Fatalf("%d entries", len(got))
	}
	var values []string
	for _, a := range got[0].Attributes {
		if a.Type == "supportedSASLMechanisms" {
			values = a.Values
		}
	}
	if len(values) != 2 {
		t.Fatalf("mechanisms = %v", values)
	}
	for _, v := range values {
		if v != MechExternal && v != MechPlain {
			t.Errorf("%q advertised but not implemented",
				v)
		}
	}
}
