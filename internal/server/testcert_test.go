package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// testTLS returns a server config and a client config that
// trusts it, generated fresh per test run. Self-signed and
// short-lived: this is test scaffolding, not a key store.
func testTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(
		elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, leaf := selfSign(t, key)

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	srv := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
			Leaf:        leaf,
		}},
		MinVersion: tls.VersionTLS12,
	}
	cli := &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
	return srv, cli
}

// selfSign issues a self-signed certificate for key.
func selfSign(
	t *testing.T, key *ecdsa.PrivateKey,
) ([]byte, *x509.Certificate) {
	t.Helper()
	tmpl := certTemplate()
	der, err := x509.CreateCertificate(
		rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, leaf
}

// certTemplate describes the test certificate.
func certTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "olivine-test",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
		DNSNames: []string{"localhost"},
	}
}
