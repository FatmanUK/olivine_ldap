package store

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/FatmanUK/openldap_olivine/internal/dn"
	"github.com/FatmanUK/openldap_olivine/internal/schema"
)

var (
	ErrNotFound = errors.New("store: no such entry")
	ErrExists   = errors.New("store: entry already exists")
	ErrNoParent = errors.New("store: parent does not exist")
)

// Store persists entries in Postgres.
type Store struct {
	db     *gorm.DB
	schema *schema.Registry
	// configState holds the configuration in force — the
	// suffixes, the access policy, the root identity and the
	// limits. It lives behind an atomic pointer because
	// cn=config is writable: see settings.
	configState
}

// New returns a Store over an open GORM connection.
func New(
	db *gorm.DB, reg *schema.Registry,
) (*Store, error) {
	if db == nil {
		return nil, errors.New("store: nil database")
	}
	if reg == nil {
		return nil, errors.New("store: nil schema")
	}
	return &Store{db: db, schema: reg}, nil
}

// Migrate creates or updates the tables.
//
// Crash-only architecture: there is no separate migration step
// an operator must remember, and no save or restore routine. The
// server brings the schema up to date on start and is expected
// to be killed rather than shut down.
func (s *Store) Migrate() error {
	return s.db.AutoMigrate(
		&Entry{}, &Value{}, &Setting{})
}

// revDN reverses a normalised DN's RDNs, so that "is under"
// becomes a prefix test. See the Entry doc comment.
func revDN(normalised string) string {
	parts := strings.Split(normalised, ",")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ",")
}

// parentOf returns the normalised parent of a normalised DN,
// empty at the top.
func parentOf(normalised string) string {
	_, rest, found := strings.Cut(normalised, ",")
	if !found {
		return ""
	}
	return rest
}

// normalise reduces a DN to its normal and pretty forms.
func (s *Store) normalise(
	raw string,
) (norm, pretty string, err error) {
	norm, err = dn.Normalise(s.schema, raw)
	if err != nil {
		return "", "", fmt.Errorf("normalising %q: %w",
			raw, err)
	}
	pretty, err = dn.Pretty(s.schema, raw)
	if err != nil {
		return "", "", fmt.Errorf("prettifying %q: %w",
			raw, err)
	}
	return norm, pretty, nil
}
