package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FatmanUK/olivine_ldap/internal/ber"
	"github.com/FatmanUK/olivine_ldap/internal/ldap"
)

func TestConfigFromEnvNeedsCert(t *testing.T) {
	t.Setenv("OLIVINE_TLS_CERT", "")
	t.Setenv("OLIVINE_TLS_KEY", "")
	if _, err := configFromEnv(); err == nil {
		t.Fatal("missing cert should be an error")
	}
}

func TestConfigFromEnvDefaultsToLDAPS(t *testing.T) {
	t.Setenv("OLIVINE_LISTEN", "")
	t.Setenv("OLIVINE_TLS_CERT", "c")
	t.Setenv("OLIVINE_TLS_KEY", "k")
	c, err := configFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	// 636 is ldaps. There is no 389 listener.
	if c.addr != ":636" {
		t.Errorf("addr = %q, want :636", c.addr)
	}
}

// TestRunServesOverTLS drives the daemon's own configuration
// and startup path, not just the server package, so a wiring
// mistake in run() is caught.
func TestRunServesOverTLS(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	writeTestKeyPair(t, certPath, keyPath)

	t.Setenv("OLIVINE_LISTEN", "127.0.0.1:0")
	t.Setenv("OLIVINE_TLS_CERT", certPath)
	t.Setenv("OLIVINE_TLS_KEY", keyPath)

	cfg, err := configFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	addr := serveInBackground(t, cfg)

	m := probe(t, addr)
	if m.Op != ldap.ResDelete {
		t.Errorf("op = %#x, want %#x", m.Op, ldap.ResDelete)
	}
	if m.ID != 3 {
		t.Errorf("id = %d, want 3", m.ID)
	}
}

// probe sends one DelRequest and returns the reply. An
// unimplemented operation must still draw a well-formed
// refusal, not silence.
func probe(t *testing.T, addr string) *ldap.Message {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetDeadline(
		time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(deleteRequest(t)); err != nil {
		t.Fatal(err)
	}
	pkt, err := ber.ReadPacket(c, ber.MaxIncomingAuth)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ldap.ParseMessage(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// deleteRequest builds a DelRequest, whose body is just the DN
// — the simplest operation to send.
func deleteRequest(t *testing.T) []byte {
	t.Helper()
	e := ber.NewEncoder()
	e.Begin(ldap.TagMessage)
	e.Int32(ldap.TagMsgID, 3)
	e.OctetString(ldap.ReqDelete,
		[]byte("cn=x,dc=example,dc=com"))
	e.End()
	out, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMissingCertFileIsReported(t *testing.T) {
	err := run(config{
		addr: "127.0.0.1:0",
		cert: filepath.Join(t.TempDir(), "absent.pem"),
		key:  filepath.Join(t.TempDir(), "absent.key"),
	})
	if err == nil {
		t.Fatal("absent certificate should fail")
	}
	if _, statErr := os.Stat("absent.pem"); statErr == nil {
		t.Fatal("test wrote a file it should not have")
	}
}
