package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/FatmanUK/openldap_olivine/internal/server"
	"github.com/FatmanUK/openldap_olivine/internal/store"
)

// config is the daemon's whole configuration.
type config struct {
	addr string
	cert string
	key  string
	// dsn is the Postgres connection string. Empty means no
	// backend, and every operation then answers
	// unwillingToPerform.
	dsn string
	// suffixes are the naming contexts this server holds, as
	// slapd takes from `suffix "dc=example,dc=com"`.
	suffixes []string
	// schemaFiles are extra .schema files to load beyond the
	// built-in set.
	schemaFiles []string
	// aclFile holds access directives in slapd.conf syntax.
	// Empty means slapd's default of read on everything.
	aclFile string
	// rootDN and rootPassword are the administrative identity,
	// as slapd's rootdn and rootpw. The password is a hash in
	// the same format userPassword uses.
	rootDN       string
	rootPassword string
}

// defaultAddr is the ldaps port. There is no 389 listener:
// Olivine is TLS-only.
const defaultAddr = ":636"

var errNoCert = errors.New(
	"OLIVINE_TLS_CERT and OLIVINE_TLS_KEY are required")

// configFromEnv reads the configuration from the environment.
func configFromEnv() (config, error) {
	c := config{
		addr:        os.Getenv("OLIVINE_LISTEN"),
		cert:        os.Getenv("OLIVINE_TLS_CERT"),
		key:         os.Getenv("OLIVINE_TLS_KEY"),
		dsn:         os.Getenv("OLIVINE_DSN"),
		suffixes:    splitList(os.Getenv("OLIVINE_SUFFIX")),
		schemaFiles: splitList(os.Getenv("OLIVINE_SCHEMA")),
		aclFile:     os.Getenv("OLIVINE_ACL_FILE"),
		rootDN:      os.Getenv("OLIVINE_ROOT_DN"),
		rootPassword: os.Getenv(
			"OLIVINE_ROOT_PASSWORD_HASH"),
	}
	if c.addr == "" {
		c.addr = defaultAddr
	}
	if c.cert == "" || c.key == "" {
		return c, errNoCert
	}
	return c, nil
}

// run starts the server and blocks.
func run(c config) error {
	pair, err := tls.LoadX509KeyPair(c.cert, c.key)
	if err != nil {
		return err
	}
	backend, err := openBackend(c)
	if err != nil {
		return err
	}
	s, err := server.New(server.Config{
		Addr:    c.addr,
		Backend: backend,
		TLS: &tls.Config{
			Certificates: []tls.Certificate{pair},
			MinVersion:   tls.VersionTLS12,
		},
	})
	if err != nil {
		return err
	}
	if err := s.Listen(); err != nil {
		return err
	}
	log.Printf("olivined listening on %s", s.Addr())
	return s.Serve()
}

// printHash writes an Argon2id hash for a password.
//
// Separate from the server so an operator can produce a value for
// OLIVINE_ROOT_PASSWORD_HASH without a running directory, which is
// slappasswd's job upstream.
func printHash(password string) {
	hashed, err := store.HashPassword(password)
	if err != nil {
		log.Fatalf("olivined: hashing: %v", err)
	}
	fmt.Println(hashed)
}
