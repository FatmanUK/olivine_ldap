package golden

import (
	"fmt"
	"os"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/FatmanUK/openldap_olivine/internal/schema"
	"github.com/FatmanUK/openldap_olivine/internal/store"
)

// seedLDIF is the tree both implementations are given.
//
// Deliberately small and entirely within what Olivine supports,
// because a comparison is only informative when both sides were
// asked the same answerable question.
var seedLDIF = []struct {
	DN    string
	Attrs []store.Attribute
}{
	// top + organization is the structural pair, dcObject the
	// auxiliary that permits dc. `domain` would be the obvious
	// choice and is wrong here: it lives in cosine.schema, not
	// core.schema, and slapd rejects the entry with
	// "objectClass: value #1 invalid per syntax". Olivine
	// accepted it, because it does no schema checking yet —
	// see BOOTSTRAP.md §3.1.
	{"dc=example,dc=com", []store.Attribute{
		{Type: "objectClass", Values: []string{
			"top", "organization", "dcObject"}},
		{Type: "o", Values: []string{"example"}},
		{Type: "dc", Values: []string{"example"}},
	}},
	{"ou=people,dc=example,dc=com", []store.Attribute{
		{Type: "objectClass",
			Values: []string{"organizationalUnit"}},
		{Type: "ou", Values: []string{"people"}},
	}},
	{"cn=Alice,ou=people,dc=example,dc=com",
		[]store.Attribute{
			{Type: "objectClass",
				Values: []string{"person"}},
			{Type: "cn", Values: []string{"Alice"}},
			{Type: "sn", Values: []string{"Anderson"}},
		}},
	{"cn=Bob,ou=people,dc=example,dc=com",
		[]store.Attribute{
			{Type: "objectClass",
				Values: []string{"person"}},
			{Type: "cn", Values: []string{"Bob"}},
			{Type: "sn", Values: []string{"Brown"}},
		}},
	// Three devices carrying serialNumber, whose matching
	// rule is caseIgnoreMatch over a DirectoryString, and
	// telephoneNumber on the organizationalRole entries
	// below. The values are chosen so that a string
	// comparison and a numeric one disagree: "9" sorts after
	// "10" as text and before it as a number.
	{"cn=dev9,ou=people,dc=example,dc=com",
		[]store.Attribute{
			{Type: "objectClass",
				Values: []string{"device"}},
			{Type: "cn", Values: []string{"dev9"}},
			{Type: "serialNumber",
				Values: []string{"9"}},
		}},
	{"cn=dev10,ou=people,dc=example,dc=com",
		[]store.Attribute{
			{Type: "objectClass",
				Values: []string{"device"}},
			{Type: "cn", Values: []string{"dev10"}},
			{Type: "serialNumber",
				Values: []string{"10"}},
		}},
	{"cn=dev100,ou=people,dc=example,dc=com",
		[]store.Attribute{
			{Type: "objectClass",
				Values: []string{"device"}},
			{Type: "cn", Values: []string{"dev100"}},
			{Type: "serialNumber",
				Values: []string{"100"}},
		}},
	// uidNumber declares ORDERING integerOrderingMatch, so a
	// >= filter on it orders numerically: 9 < 10 < 100, where
	// a string comparison would put "10" and "100" before
	// "9". extensibleObject carries the attribute, since
	// device does not permit it and posixAccount would drag
	// in several more MUST attributes.
	{"cn=num9,ou=people,dc=example,dc=com",
		[]store.Attribute{
			{Type: "objectClass", Values: []string{
				"device", "extensibleObject"}},
			{Type: "cn", Values: []string{"num9"}},
			{Type: "uidNumber", Values: []string{"9"}},
		}},
	{"cn=num10,ou=people,dc=example,dc=com",
		[]store.Attribute{
			{Type: "objectClass", Values: []string{
				"device", "extensibleObject"}},
			{Type: "cn", Values: []string{"num10"}},
			{Type: "uidNumber", Values: []string{"10"}},
		}},
	{"cn=num100,ou=people,dc=example,dc=com",
		[]store.Attribute{
			{Type: "objectClass", Values: []string{
				"device", "extensibleObject"}},
			{Type: "cn", Values: []string{"num100"}},
			{Type: "uidNumber", Values: []string{"100"}},
		}},
}

// OpenStore builds a seeded Olivine store for the harness.
//
// Returns nil when OLIVINE_TEST_DSN is unset, so the
// protocol-only scripts still run without Postgres.
func OpenStore() (*store.Store, error) {
	dsn := os.Getenv("OLIVINE_TEST_DSN")
	if dsn == "" {
		return nil, nil
	}
	reg, err := harnessSchema()
	if err != nil {
		return nil, err
	}
	db, err := openGolden(dsn)
	if err != nil {
		return nil, err
	}
	s, err := store.New(db, reg)
	if err != nil {
		return nil, err
	}
	if err := s.Migrate(); err != nil {
		return nil, err
	}
	if err := s.AddSuffix(baseDN); err != nil {
		return nil, err
	}
	// The same administrator the oracle's slapd.conf declares,
	// so a script can bind as it on both sides. slapd's rootdn
	// has no entry; neither does Olivine's.
	hashed, err := store.HashPassword(rootPW)
	if err != nil {
		return nil, err
	}
	if err := s.SetRootDN(rootDN, hashed); err != nil {
		return nil, err
	}
	return s, seed(s)
}

// baseDN is the suffix both implementations serve.
const baseDN = "dc=example,dc=com"

// seed loads the fixture, ignoring entries already present so a
// repeated run is harmless.
func seed(s *store.Store) error {
	for _, e := range seedLDIF {
		_, err := s.Add(e.DN, e.Attrs)
		if err != nil &&
			!strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("seeding %s: %w", e.DN, err)
		}
	}
	return nil
}

// harnessSchema is the schema Olivine ships with.
//
// The embedded set is derived from slapd's own cn=Subschema for
// exactly the files the oracle's slapd.conf includes — core,
// cosine and nis — so the two sides start from the same schema
// without this reading the submodule.
func harnessSchema() (*schema.Registry, error) {
	return schema.NewStandardRegistry()
}

// openGolden connects to a scratch schema named for the harness.
//
// The schema goes in the connection string, never a
// SET search_path: GORM pools connections, so a SET reaches one
// of them and every other query lands in public.
func openGolden(dsn string) (*gorm.DB, error) {
	const scratch = "olivine_golden"
	admin, err := gorm.Open(postgres.Open(dsn),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		return nil, err
	}
	err = admin.Exec(fmt.Sprintf(
		`DROP SCHEMA IF EXISTS %q CASCADE`,
		scratch)).Error
	if err != nil {
		return nil, err
	}
	err = admin.Exec(fmt.Sprintf(`CREATE SCHEMA %q`,
		scratch)).Error
	if err != nil {
		return nil, err
	}
	return gorm.Open(postgres.Open(
		dsn+" search_path="+scratch), &gorm.Config{
		Logger:                 logger.Discard,
		TranslateError:         true,
		SkipDefaultTransaction: true,
	})
}

// NewBackend wraps a store for the harness, so the test file
// need not import internal/store.
func NewBackend(s *store.Store) Backend {
	return store.NewAdapter(s)
}
