package golden

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
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
TLSCACertificateFile /config/ca.pem
# try, not demand: a certificate is an identity for SASL
# EXTERNAL to bind as, not an admission ticket, so a client
# that presents none is still served.
TLSVerifyClient try

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
	// The shared material, not a fresh set: see sharedTLS.
	return copyTLSMaterial(dir)
}

// writeKeyPair generates the oracle's TLS material: a CA, a
// server certificate signed by it, and a client certificate for
// SASL EXTERNAL to bind as.
//
// A CA rather than a self-signed server certificate, because
// EXTERNAL needs a client certificate the server will accept, and
// both sides have to trust the same issuer for the comparison to
// mean anything.
func writeKeyPair(dir string) error {
	ca, caKey, err := makeCA()
	if err != nil {
		return err
	}
	if err := writeCA(dir, ca, caKey); err != nil {
		return err
	}
	if err := writeSigned(dir, "", ca, caKey,
		serverSubject()); err != nil {
		return err
	}
	return writeSigned(dir, "client", ca, caKey,
		clientSubject())
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
