package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/FatmanUK/olivine_ldap/internal/server"
	"github.com/FatmanUK/olivine_ldap/internal/store"
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
	// sizeLimit and timeLimit are the administrative search
	// limits, as slapd's sizelimit and timelimit. Zero means
	// slapd's own defaults.
	sizeLimit int32
	timeLimit int32
	// configRefresh is how often the running configuration is
	// re-read from the database, so a change made through one
	// replica reaches the others. Zero disables the refresh,
	// which only makes sense for a single instance.
	configRefresh time.Duration
	// keytab is the Kerberos keytab holding the service's
	// long-term keys. Without it GSSAPI is neither advertised
	// nor accepted. Environmental, like the TLS material and
	// for the same reason: it is a file the process must read
	// before it can serve anything.
	keytab string
	// clientCA, when set, makes the server request a client
	// certificate and verify it against these authorities. A
	// client that presents none is still served, as slapd's
	// `TLSVerifyClient try` does: the certificate is an
	// identity for SASL EXTERNAL, not an admission ticket.
	clientCA string
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
		sizeLimit: envInt("OLIVINE_SIZELIMIT"),
		timeLimit: envInt("OLIVINE_TIMELIMIT"),
		clientCA:  os.Getenv("OLIVINE_TLS_CLIENT_CA"),
		keytab:    os.Getenv("OLIVINE_KRB5_KEYTAB"),
		configRefresh: refreshInterval(
			"OLIVINE_CONFIG_REFRESH"),
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
	clientCAs, err := loadClientCAs(c)
	if err != nil {
		return err
	}
	s, err := server.New(server.Config{
		Addr:      c.addr,
		Backend:   backend,
		ClientCAs: clientCAs,
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

// envInt reads a non-negative integer from the environment, zero
// when unset or unreadable.
//
// A malformed value reads as unset rather than failing the start:
// the limits have working defaults, and a directory that refuses
// to come up over a typo in an optional tuning knob is worse than
// one that uses slapd's own numbers.
func envInt(name string) int32 {
	raw := os.Getenv(name)
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		log.Printf("olivined: ignoring %s=%q", name, raw)
		return 0
	}
	return int32(n)
}

// defaultRefresh is how often a replica re-reads cn=config.
//
// Thirty seconds is a compromise with no upstream to copy: slapd
// has no equivalent, because its configuration is local to the
// process. Short enough that an operator does not wonder whether
// a change took, long enough that a dozen replicas are not a
// load on the database by themselves.
const defaultRefresh = 30 * time.Second

// refreshInterval reads the refresh period in seconds.
//
// An explicit zero disables it; anything unreadable falls back to
// the default, for the same reason envInt does.
func refreshInterval(name string) time.Duration {
	raw := os.Getenv(name)
	if raw == "" {
		return defaultRefresh
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		log.Printf("olivined: ignoring %s=%q", name, raw)
		return defaultRefresh
	}
	return time.Duration(n) * time.Second
}

// loadClientCAs reads the authorities that may issue client
// certificates, or nil when none is configured.
func loadClientCAs(c config) (*x509.CertPool, error) {
	if c.clientCA == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(c.clientCA)
	if err != nil {
		return nil, fmt.Errorf("client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf(
			"client CA %s holds no certificate",
			c.clientCA)
	}
	return pool, nil
}
