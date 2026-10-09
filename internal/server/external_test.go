package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// clientCert issues a client certificate with the given subject.
func clientCert(
	t *testing.T, name pkix.Name,
) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(
		elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      name,
		NotBefore:    certTemplate().NotBefore,
		NotAfter:     certTemplate().NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}
	der, err := x509.CreateCertificate(
		rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der}, PrivateKey: key,
	}
}

// The DN a certificate yields must be in LDAP order — most
// specific first — not the certificate's own, which runs the other
// way. slapd's ldapwhoami reported
// cn=client,o=Olivine,c=GB for a subject written
// "C=GB, O=Olivine, CN=client".
func TestPeerDNIsInLDAPOrder(t *testing.T) {
	cert := clientCert(t, pkix.Name{
		Country:      []string{"GB"},
		Organization: []string{"Olivine"},
		CommonName:   "client",
	})
	parsed, err := x509.ParseCertificate(
		cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	got := subjectDN(parsed.Subject)
	want := "CN=client,O=Olivine,C=GB"
	if got != want {
		t.Errorf("DN = %q, want %q", got, want)
	}
}

// A connection with no client certificate yields no identity, so
// EXTERNAL has nothing to bind as.
func TestPeerDNEmptyWithoutCertificate(t *testing.T) {
	fake := newFake()
	_, cliTLS, addr := startWith(t, fake)
	c := dial(t, cliTLS, addr)

	e := ber.NewEncoder()
	e.Int32(ber.TagInteger, 3)
	e.String(ldap.TagLDAPDN, "")
	e.Begin(ldap.AuthSASL)
	e.String(ber.TagOctetString, "EXTERNAL")
	e.End()
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(
		envelope(t, 1, ldap.ReqBind, body)); err != nil {
		t.Fatal(err)
	}
	readMessage(t, c)
	if len(fake.bindCalls) != 1 {
		t.Fatalf("%d bind calls", len(fake.bindCalls))
	}
	if ext := fake.bindCalls[0].External; ext != "" {
		t.Errorf("External = %q, want empty", ext)
	}
	if fake.bindCalls[0].Mechanism != "EXTERNAL" {
		t.Errorf("mechanism = %q",
			fake.bindCalls[0].Mechanism)
	}
}

// With a certificate the server hands its DN to the backend, which
// is the only part that can turn it into a bound identity.
func TestExternalIdentityReachesTheBackend(t *testing.T) {
	fake := newFake()
	c := dialWithClientCert(t, fake)
	e := ber.NewEncoder()
	e.Int32(ber.TagInteger, 3)
	e.String(ldap.TagLDAPDN, "")
	e.Begin(ldap.AuthSASL)
	e.String(ber.TagOctetString, "EXTERNAL")
	e.End()
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(
		envelope(t, 1, ldap.ReqBind, body)); err != nil {
		t.Fatal(err)
	}
	readMessage(t, c)
	if len(fake.bindCalls) != 1 {
		t.Fatalf("%d bind calls", len(fake.bindCalls))
	}
	want := "CN=client,O=Olivine,C=GB"
	if got := fake.bindCalls[0].External; got != want {
		t.Errorf("External = %q, want %q", got, want)
	}
}

// dialWithClientCert starts a server that requests a client
// certificate and connects presenting one.
//
// Any certificate is accepted: what is under test is that the DN
// arrives, not the trust decision.
func dialWithClientCert(
	t *testing.T, b Backend,
) *tls.Conn {
	t.Helper()
	srvTLS, cliTLS := testTLS(t)
	cert := clientCert(t, pkix.Name{
		Country:      []string{"GB"},
		Organization: []string{"Olivine"},
		CommonName:   "client",
	})
	srvTLS = srvTLS.Clone()
	srvTLS.ClientAuth = tls.RequestClientCert
	cliTLS = cliTLS.Clone()
	cliTLS.Certificates = []tls.Certificate{cert}

	s, err := New(Config{
		Addr: "127.0.0.1:0", TLS: srvTLS, Backend: b,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() { _ = s.Close() })
	return dial(t, cliTLS, s.Addr().String())
}

// While a SASL bind is part-way through, nothing else may run:
// connection.c:1103-1111 answers operationsError with
// "SASL bind in progress".
func TestSASLInProgressBlocksOtherOperations(t *testing.T) {
	fake := newFake()
	fake.result = ldap.Result{
		Code: ldap.SASLBindInProgress,
	}
	_, cliTLS, addr := startWith(t, fake)
	c := dial(t, cliTLS, addr)

	e := ber.NewEncoder()
	e.Int32(ber.TagInteger, 3)
	e.String(ldap.TagLDAPDN, "")
	e.Begin(ldap.AuthSASL)
	e.String(ber.TagOctetString, "GSSAPI")
	e.End()
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(
		envelope(t, 1, ldap.ReqBind, body)); err != nil {
		t.Fatal(err)
	}
	readMessage(t, c)

	// A search now must be refused, not run.
	if _, err := c.Write(envelope(
		t, 2, ldap.ReqSearch, searchBody(t))); err != nil {
		t.Fatal(err)
	}
	m := readMessage(t, c)
	if code := resultCode(t, m); code !=
		ldap.OperationsError {
		t.Errorf("code = %v, want operationsError", code)
	}
	if len(fake.searchCalls) != 0 {
		t.Error("the search reached the backend")
	}
}
