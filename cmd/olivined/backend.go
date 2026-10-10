package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/FatmanUK/olivine_ldap/internal/acl"
	"github.com/FatmanUK/olivine_ldap/internal/gss"
	"github.com/FatmanUK/olivine_ldap/internal/schema"
	"github.com/FatmanUK/olivine_ldap/internal/server"
	"github.com/FatmanUK/olivine_ldap/internal/store"
)

// openBackend builds the store from the environment.
//
// Returns a nil Backend when no database is configured, which
// leaves every operation unwillingToPerform. That is a usable
// state — a server that answers honestly about having no data
// beats one that will not start — and it keeps the TLS listener
// testable without Postgres.
func openBackend(c config) (server.Backend, error) {
	if c.dsn == "" {
		return nil, nil
	}
	db, err := gorm.Open(postgres.Open(c.dsn), &gorm.Config{
		Logger:                 logger.Discard,
		TranslateError:         true,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	reg, err := loadSchema(c)
	if err != nil {
		return nil, err
	}
	s, err := store.New(db, reg)
	if err != nil {
		return nil, err
	}
	// Crash-only: the schema is brought up to date on start,
	// not by a migration step an operator must remember.
	if err := s.Migrate(); err != nil {
		return nil, fmt.Errorf("migrating: %w", err)
	}
	if err := applyKeytab(s, c); err != nil {
		return nil, err
	}
	if err := bootstrap(s, c); err != nil {
		return nil, err
	}
	// Changes made through another replica are picked up here.
	// There is no notification channel: Postgres has LISTEN,
	// but a replica that missed one while reconnecting would
	// stay wrong indefinitely, and a poll cannot.
	go refreshConfig(s, c.configRefresh)
	return store.NewAdapter(s), nil
}

// applyKeytab turns GSSAPI on, if a keytab is configured.
//
// A keytab that cannot be read fails the start rather than
// quietly disabling the mechanism: an operator who named one
// means to serve Kerberos, and a server that came up advertising
// EXTERNAL and PLAIN instead would look like a client problem.
func applyKeytab(s *store.Store, c config) error {
	if c.keytab == "" {
		return nil
	}
	acceptor, err := gss.NewAcceptor(c.keytab)
	if err != nil {
		return err
	}
	s.SetGSSAcceptor(acceptor)
	return nil
}

// bootstrap settles the configuration.
//
// The environment is read as *defaults for first boot*: what the
// database already holds wins, because that is where a change
// made over LDAP lands and a restarting replica must not revert
// it. See store.Config.
func bootstrap(s *store.Store, c config) error {
	access, err := accessDirectives(c)
	if err != nil {
		return err
	}
	if err := checkRootDN(c); err != nil {
		return err
	}
	return s.Bootstrap(store.Config{
		Suffixes:         c.suffixes,
		Access:           access,
		RootDN:           c.rootDN,
		RootPasswordHash: c.rootPassword,
		Limits: store.Limits{
			Size: c.sizeLimit, Time: c.timeLimit,
		},
	})
}

// refreshConfig re-reads the configuration on a timer.
//
// A failed read is logged and the configuration in force is
// kept. That is not a departure from crash-only: the database
// being unreachable already fails every operation that needs it,
// and swapping in an empty configuration — or dying — because one
// poll failed would turn a transient fault into an outage.
func refreshConfig(s *store.Store, every time.Duration) {
	if every <= 0 {
		return
	}
	for range time.Tick(every) {
		if err := s.LoadConfig(); err != nil {
			log.Printf("olivined: refreshing "+
				"configuration: %v", err)
		}
	}
}

// checkRootDN refuses a half-configured administrator.
//
// The password is supplied already hashed, so a plaintext
// credential never sits in the environment where `ps` and a
// container inspect would show it. `olivined -hash` prints one.
func checkRootDN(c config) error {
	if c.rootDN == "" || c.rootPassword != "" {
		return nil
	}
	return errors.New(
		"OLIVINE_ROOT_DN needs " +
			"OLIVINE_ROOT_PASSWORD_HASH")
}

// accessDirectives reads the access file, if any.
//
// No file means no directives, which is slapd's default of read
// on everything (frontend.c:99). That is a deliberate default
// rather than an omission: a server that refused to start without
// an ACL file would be harder to stand up, and one that defaulted
// to *deny* would differ from the C.
//
// The directives become olcAccess values, so a policy seeded
// from a file can be read back — and changed — over LDAP.
func accessDirectives(c config) ([]string, error) {
	if c.aclFile == "" {
		return nil, nil
	}
	text, err := os.ReadFile(c.aclFile)
	if err != nil {
		return nil, fmt.Errorf("access file: %w", err)
	}
	directives, err := acl.Split(string(text))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.aclFile, err)
	}
	return directives, nil
}

// loadSchema builds the schema registry.
//
// The embedded standard set — what schema_init.c hardcodes plus
// core, cosine and nis — so a server starts with no files to find.
// The built-in set alone is not enough: dc, ou and person come
// from core.schema, and a daemon loading only the hardcoded
// definitions cannot even normalise its own suffix. The container
// smoke test found that, because a scratch image has no .schema
// files anywhere.
//
// OLIVINE_SCHEMA adds more on top, for a directory that needs a
// schema Olivine does not ship.
func loadSchema(c config) (*schema.Registry, error) {
	reg, err := schema.NewStandardRegistry()
	if err != nil {
		return nil, err
	}
	for _, path := range c.schemaFiles {
		if err := loadOne(reg, path); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

// loadOne reads one .schema file.
func loadOne(reg *schema.Registry, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("schema file: %w", err)
	}
	defer f.Close()
	if err := schema.LoadFile(reg, f); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// splitList splits a colon-separated environment value.
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ":")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
