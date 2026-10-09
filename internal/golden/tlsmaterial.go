package golden

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"path/filepath"
	"time"
)

// ClientSubjectDN is the DN a SASL EXTERNAL bind should produce
// from the client certificate below, in LDAP order.
//
// The certificate's own subject runs the other way —
// "C=GB, O=Olivine, CN=olivine-client" — so a DN built in
// certificate order would look plausible and name nothing.
// Verified against slapd, whose ldapwhoami reported exactly this
// for the same subject.
const ClientSubjectDN = "CN=olivine-client,O=Olivine,C=GB"

// serverSubject is the server certificate's subject.
func serverSubject() pkix.Name {
	return pkix.Name{CommonName: "localhost"}
}

// clientSubject is the client certificate's subject.
func clientSubject() pkix.Name {
	return pkix.Name{
		Country:      []string{"GB"},
		Organization: []string{"Olivine"},
		CommonName:   "olivine-client",
	}
}

// makeCA issues the test certificate authority.
func makeCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(
		elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Olivine Golden CA",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(der)
	return ca, key, err
}

// writeCA writes the authority's certificate.
func writeCA(
	dir string, ca *x509.Certificate,
	key *ecdsa.PrivateKey,
) error {
	return writePEMFile(filepath.Join(dir, "ca.pem"),
		"CERTIFICATE", ca.Raw)
}

// writeSigned issues and writes a certificate signed by the CA.
//
// An empty prefix writes cert.pem and key.pem, which is what
// slapd.conf names for the server; a prefix writes
// <prefix>-cert.pem and <prefix>-key.pem.
func writeSigned(
	dir, prefix string, ca *x509.Certificate,
	caKey *ecdsa.PrivateKey, subject pkix.Name,
) error {
	key, err := ecdsa.GenerateKey(
		elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := signFor(ca, caKey, &key.PublicKey, subject)
	if err != nil {
		return err
	}
	certName, keyName := "cert.pem", "key.pem"
	if prefix != "" {
		certName = prefix + "-cert.pem"
		keyName = prefix + "-key.pem"
	}
	err = writePEMFile(filepath.Join(dir, certName),
		"CERTIFICATE", der)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	// slapd reads these as the container user, so they must be
	// world-readable inside the read-only mount.
	return writePEMFile(filepath.Join(dir, keyName),
		"EC PRIVATE KEY", keyDER)
}

// signFor issues one leaf certificate.
func signFor(
	ca *x509.Certificate, caKey *ecdsa.PrivateKey,
	pub *ecdsa.PublicKey, subject pkix.Name,
) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}
	return x509.CreateCertificate(
		rand.Reader, tmpl, ca, pub, caKey)
}
