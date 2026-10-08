package main

import (
	"crypto/tls"
	"errors"
	"log"
	"os"

	"github.com/FatmanUK/openldap_olivine/internal/server"
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
