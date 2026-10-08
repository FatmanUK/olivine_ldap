package store

import (
	"fmt"
	"os"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testStore returns a Store over a throwaway schema.
//
// The scratch schema goes in the *connection string*, never a
// `SET search_path`. GORM pools connections: a SET reaches
// whichever connection happened to run it and every other query
// lands in public, so the tests would quietly write to a real
// world. BOOTSTRAP.md §3.4 records this; it is paid for in
// blood.
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := testDSN()
	if dsn == "" {
		t.Skipf("neither %s nor %s is set; see "+
			"internal/store/README",
			envTestURL, envTestDSN)
	}
	name := scratchSchema(t, dsn)
	db := openScratch(t, dsn, name)

	s, err := New(db, testSchema(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := s.AddSuffix("dc=example,dc=com"); err != nil {
		t.Fatal(err)
	}
	return s
}

// scratchSchema creates a schema named after the test and
// drops it afterwards.
func scratchSchema(t *testing.T, dsn string) string {
	t.Helper()
	admin, err := gorm.Open(postgres.Open(dsn),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Skipf("cannot reach Postgres: %v", err)
	}
	name := scratchName(t)
	err = admin.Exec(fmt.Sprintf(
		`DROP SCHEMA IF EXISTS %q CASCADE`, name)).Error
	if err != nil {
		t.Fatal(err)
	}
	err = admin.Exec(fmt.Sprintf(
		`CREATE SCHEMA %q`, name)).Error
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = admin.Exec(fmt.Sprintf(
			`DROP SCHEMA IF EXISTS %q CASCADE`,
			name)).Error
		sqlDB, err := admin.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})
	return name
}

// testDSN returns the test connection string, preferring the
// CI's variable.
func testDSN() string {
	if dsn := os.Getenv(envTestURL); dsn != "" {
		return dsn
	}
	return os.Getenv(envTestDSN)
}

// openScratch connects with the scratch schema named in the
// connection string.
func openScratch(
	t *testing.T, dsn, name string,
) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(
		postgres.Open(withSearchPath(dsn, name)),
		&gorm.Config{
			Logger:                 logger.Discard,
			TranslateError:         true,
			SkipDefaultTransaction: true,
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}
