package server

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/FatmanUK/olivine_ldap/internal/ber"
	"github.com/FatmanUK/olivine_ldap/internal/ldap"
)

func TestNewRequiresTLS(t *testing.T) {
	// TLS-only is structural: no certificate is a
	// configuration error, not a reason to serve cleartext.
	if _, err := New(Config{Addr: "127.0.0.1:0"}); !errors.Is(
		err, ErrNoTLS) {
		t.Fatalf("err = %v, want ErrNoTLS", err)
	}
}

// start brings up a Server with no backend, which is what the
// protocol-level tests want.
func start(t *testing.T) (*Server, *tls.Config, string) {
	t.Helper()
	return startWith(t, nil)
}

// startWith brings up a Server on an ephemeral port with the
// given backend.
func startWith(
	t *testing.T, b Backend,
) (*Server, *tls.Config, string) {
	t.Helper()
	srvTLS, cliTLS := testTLS(t)
	s, err := New(Config{
		Addr: "127.0.0.1:0", TLS: srvTLS, Backend: b,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	addr := s.Addr().String()
	go func() { _ = s.Serve() }()
	t.Cleanup(func() { _ = s.Close() })
	return s, cliTLS, addr
}

// dial opens a TLS connection to the test server.
func dial(
	t *testing.T, cliTLS *tls.Config, addr string,
) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", addr, cliTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.SetDeadline(
		time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestServerRefusesCleartext(t *testing.T) {
	_, _, addr := start(t)
	// A plain TCP client speaking LDAP gets no LDAP answer:
	// the TLS handshake fails first.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetDeadline(
		time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	packet := envelope(t, 1, ldap.ReqUnbind, nil)
	if _, err := c.Write(packet); err != nil {
		return // refused outright is fine too
	}
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("cleartext client got a reply")
	}
}

func TestUnbindClosesWithoutReply(t *testing.T) {
	_, cliTLS, addr := start(t)
	c := dial(t, cliTLS, addr)

	if _, err := c.Write(
		envelope(t, 1, ldap.ReqUnbind, nil)); err != nil {
		t.Fatal(err)
	}
	// RFC 4511 4.3: no response, and the server closes.
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("unbind drew a reply")
	}
}

// With no backend configured every operation is refused, which
// is what the server did before any database existed.
func TestNoBackendRefusesOperations(t *testing.T) {
	_, cliTLS, addr := start(t)
	c := dial(t, cliTLS, addr)

	body := searchBody(t)
	if _, err := c.Write(
		envelope(t, 5, ldap.ReqSearch, body)); err != nil {
		t.Fatal(err)
	}
	m := readMessage(t, c)
	if m.ID != 5 {
		t.Errorf("id = %d, want 5", m.ID)
	}
	if m.Op != ldap.ResSearchResult {
		t.Errorf("op = %#x, want %#x",
			m.Op, ldap.ResSearchResult)
	}
	if code := resultCode(t, m); code !=
		ldap.UnwillingToPerform {
		t.Errorf("code = %v, want unwillingToPerform",
			code)
	}
}

func TestStartTLSIsRefusedNotIgnored(t *testing.T) {
	_, cliTLS, addr := start(t)
	c := dial(t, cliTLS, addr)

	e := ber.NewEncoder()
	e.String(ldap.TagExopReqOID, ldap.OIDStartTLS)
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(
		envelope(t, 9, ldap.ReqExtended, body)); err != nil {
		t.Fatal(err)
	}
	m := readMessage(t, c)
	if m.Op != ldap.ResExtended {
		t.Errorf("op = %#x, want %#x",
			m.Op, ldap.ResExtended)
	}
	// Recognised and refused, not met with silence or a
	// parse error — and with operationsError, which is the
	// branch starttls.c:46-48 takes when the connection is
	// already TLS. The golden harness caught this: the first
	// version of this test asserted unwillingToPerform,
	// which was a guess.
	if code := resultCode(t, m); code !=
		ldap.OperationsError {
		t.Errorf("code = %v, want operationsError", code)
	}
}

func TestCriticalControlIsRefused(t *testing.T) {
	_, cliTLS, addr := start(t)
	c := dial(t, cliTLS, addr)

	e := ber.NewEncoder()
	e.Begin(ldap.TagMessage)
	e.Int32(ldap.TagMsgID, 11)
	e.Raw(ldap.ReqSearch, searchBody(t))
	e.Begin(ldap.TagControls)
	e.Begin(ber.TagSequence)
	e.String(ber.TagOctetString, ldap.OIDSyncRequest)
	e.Bool(ber.TagBoolean, true)
	e.End()
	e.End()
	e.End()
	packet, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(packet); err != nil {
		t.Fatal(err)
	}
	m := readMessage(t, c)
	if code := resultCode(t, m); code !=
		ldap.UnavailableCriticalExt {
		t.Errorf("code = %v, want %v",
			code, ldap.UnavailableCriticalExt)
	}
}

func TestGarbageDrawsNoticeOfDisconnection(t *testing.T) {
	_, cliTLS, addr := start(t)
	c := dial(t, cliTLS, addr)

	// A top-level element that is not an LDAPMessage.
	if _, err := c.Write(
		[]byte{0x04, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	m := readMessage(t, c)
	if m.ID != 0 {
		t.Errorf("notice id = %d, want 0", m.ID)
	}
	if m.Op != ldap.ResExtended {
		t.Errorf("op = %#x, want %#x",
			m.Op, ldap.ResExtended)
	}
	if code := resultCode(t, m); code != ldap.ProtocolError {
		t.Errorf("code = %v, want protocolError", code)
	}
}

func TestOversizeMessageIsRefused(t *testing.T) {
	_, cliTLS, addr := start(t)
	c := dial(t, cliTLS, addr)

	// Claim a length past the unauthenticated limit of
	// 262143 without sending the body.
	header := []byte{0x30, 0x84, 0x00, 0x40, 0x00, 0x00}
	if _, err := c.Write(header); err != nil {
		t.Fatal(err)
	}
	m := readMessage(t, c)
	if code := resultCode(t, m); code != ldap.ProtocolError {
		t.Errorf("code = %v, want protocolError", code)
	}
}

func TestLimitRisesAfterBind(t *testing.T) {
	// The limit is a property of the connection, and it
	// doubles-and-then-some once bound, as
	// sockbuf_max_incoming does.
	c := &conn{}
	if got := c.limit(); got != ber.MaxIncomingDefault {
		t.Errorf("unbound = %d, want %d",
			got, ber.MaxIncomingDefault)
	}
	c.bound = true
	if got := c.limit(); got != ber.MaxIncomingAuth {
		t.Errorf("bound = %d, want %d",
			got, ber.MaxIncomingAuth)
	}
}
