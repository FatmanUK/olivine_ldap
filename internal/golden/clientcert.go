package golden

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// certDir is where the per-run TLS material was written.
//
// Set when an oracle or an Olivine is started, so a client can
// find the client certificate they both trust.
var certDir string

// externalBindBody encodes a SASL EXTERNAL bind.
//
// No credentials: a credential on EXTERNAL is a proxy
// authorization identity, which slapd refuses with "proxy
// authorization not supported".
func externalBindBody() []byte {
	e := ber.NewEncoder()
	e.Int32(ber.TagInteger, ldap.Version3)
	e.String(ldap.TagLDAPDN, "")
	e.Begin(ldap.AuthSASL)
	e.String(ber.TagOctetString, "EXTERNAL")
	e.End()
	out, err := e.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}

// RunWithClientCert drives a script presenting the client
// certificate, so a SASL EXTERNAL bind has an identity.
func RunWithClientCert(
	addr string, script Script,
) (*Transcript, error) {
	cert, err := loadClientCert()
	if err != nil {
		return nil, err
	}
	c, err := tls.Dial("tcp", addr, &tls.Config{
		// The server's certificate is generated per run and
		// is not what is under test; the *client's* is.
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if err := c.SetDeadline(
		time.Now().Add(30 * time.Second)); err != nil {
		return nil, err
	}
	return runSteps(c, script)
}

// loadClientCert reads the per-run client certificate.
func loadClientCert() (tls.Certificate, error) {
	if certDir == "" {
		return tls.Certificate{}, fmt.Errorf(
			"no TLS material: start a server first")
	}
	return tls.LoadX509KeyPair(
		filepath.Join(certDir, "client-cert.pem"),
		filepath.Join(certDir, "client-key.pem"))
}

// clientCAPool reads the per-run CA, for a server that wants to
// verify client certificates.
func clientCAPool() (*x509.CertPool, error) {
	if certDir == "" {
		return nil, fmt.Errorf("no TLS material")
	}
	pem, err := os.ReadFile(
		filepath.Join(certDir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("unreadable CA")
	}
	return pool, nil
}
