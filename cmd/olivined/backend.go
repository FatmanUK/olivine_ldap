package main

import (
	"fmt"
	"os"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/FatmanUK/openldap_olivine/internal/acl"
	"github.com/FatmanUK/openldap_olivine/internal/schema"
	"github.com/FatmanUK/openldap_olivine/internal/server"
	"github.com/FatmanUK/openldap_olivine/internal/store"
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
	if err := addSuffixes(s, c.suffixes); err != nil {
		return nil, err
	}
	if err := applyPolicy(s, c); err != nil {
		return nil, err
	}
	return store.NewAdapter(s), nil
}

// applyPolicy loads the access directives, if any.
//
// No file means no directives, which is slapd's default of read
// on everything (frontend.c:99). That is a deliberate default
// rather than an omission: a server that refused to start without
// an ACL file would be harder to stand up, and one that defaulted
// to *deny* would differ from the C.
func applyPolicy(s *store.Store, c config) error {
	if c.aclFile == "" {
		return nil
	}
	text, err := os.ReadFile(c.aclFile)
	if err != nil {
		return fmt.Errorf("access file: %w", err)
	}
	policy, err := acl.Parse(string(text))
	if err != nil {
		return fmt.Errorf("%s: %w", c.aclFile, err)
	}
	s.SetPolicy(policy)
	return nil
}

// addSuffixes declares the naming contexts.
func addSuffixes(s *store.Store, suffixes []string) error {
	for _, suf := range suffixes {
		if err := s.AddSuffix(suf); err != nil {
			return fmt.Errorf(
				"suffix %q: %w", suf, err)
		}
	}
	return nil
}

// loadSchema builds the schema registry.
//
// The built-in set from schema_init.c is always present. Extra
// .schema files come from OLIVINE_SCHEMA_FILES, because dc, ou
// and person live in core.schema rather than in the C — Olivine
// does not embed a standard schema of its own yet.
func loadSchema(c config) (*schema.Registry, error) {
	reg, err := schema.NewDefaultRegistry()
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
