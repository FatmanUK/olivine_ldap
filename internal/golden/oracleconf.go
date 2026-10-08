package golden

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// slapdConf is the oracle's configuration.
//
// Deliberately minimal: back-mdb over an empty database, the
// bundled core schema, and TLS. The point is to compare
// protocol behaviour, so anything that would make the two
// servers differ for configuration reasons is left out.
// cosine and nis come along because the comparison needs an
// attribute with an ORDERING rule of its own: uidNumber declares
// integerOrderingMatch, and core.schema has nothing that does.
// nis.schema depends on cosine.schema.
const slapdConf = `include ` + schemaDir + `/core.schema
include ` + schemaDir + `/cosine.schema
include ` + schemaDir + `/nis.schema

pidfile /data/slapd.pid
argsfile /data/slapd.args

TLSCertificateFile /config/cert.pem
TLSCertificateKeyFile /config/key.pem

database mdb
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
directory /data
`

// schemaDir is where `make install` puts the bundled schema.
const schemaDir = "/opt/openldap/etc/openldap/schema"

// writeOracleConfig writes slapd.conf and a fresh key pair.
//
// extra is appended to the configuration, which is how the access
// comparison installs the same policy on both sides.
func writeOracleConfig(dir, extra string) error {
	conf := filepath.Join(dir, "slapd.conf")
	text := slapdConf + extra + "\n"
	if err := os.WriteFile(
		conf, []byte(text), 0o644); err != nil {
		return err
	}
	return writeKeyPair(dir)
}

// writeKeyPair generates the oracle's TLS certificate. It is
// self-signed and lives for an hour: the client skips
// verification, because the certificate is not under test.
func writeKeyPair(dir string) error {
	key, err := ecdsa.GenerateKey(
		elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := selfSigned(key)
	if err != nil {
		return err
	}
	err = writePEMFile(filepath.Join(dir, "cert.pem"),
		"CERTIFICATE", der)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	// slapd reads the key as the container user, so it must
	// be world-readable inside the read-only mount.
	return writePEMFile(filepath.Join(dir, "key.pem"),
		"EC PRIVATE KEY", keyDER)
}

// selfSigned issues the certificate.
func selfSigned(key *ecdsa.PrivateKey) ([]byte, error) {
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
	return x509.CreateCertificate(
		rand.Reader, tmpl, tmpl, &key.PublicKey, key)
}

// writePEMFile writes one PEM block at mode 0644.
func writePEMFile(path, kind string, der []byte) error {
	f, err := os.OpenFile(path,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	err = pem.Encode(f, &pem.Block{Type: kind, Bytes: der})
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
