package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/FatmanUK/olivine_ldap/internal/server"
)

// writeTestKeyPair writes a self-signed certificate and key.
func writeTestKeyPair(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(
		elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der := issue(t, key)
	writePEM(t, certPath, "CERTIFICATE", der)

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)
}

// issue creates the self-signed certificate.
func issue(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
		DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(
		rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// writePEM writes one PEM block.
func writePEM(
	t *testing.T, path, kind string, der []byte,
) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = pem.Encode(f, &pem.Block{
		Type: kind, Bytes: der,
	})
	if err != nil {
		t.Fatal(err)
	}
}

// serveInBackground starts a Server from cfg and returns the
// bound address. It mirrors run() but hands back the address,
// which run() cannot do because it blocks.
func serveInBackground(
	t *testing.T, cfg config,
) string {
	t.Helper()
	tlsCfg := loadPair(t, cfg)
	s, err := server.New(server.Config{
		Addr: cfg.addr, TLS: tlsCfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() { _ = s.Close() })
	return s.Addr().String()
}
