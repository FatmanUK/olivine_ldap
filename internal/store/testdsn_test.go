package store

import (
	"net/url"
	"strings"
)

// Environment variables that name the test database.
//
// TEST_DATABASE_URL is what the CI sets, as a postgres:// URL.
// OLIVINE_TEST_DSN is what `make store` sets, in libpq key-value
// form. Both are accepted because both exist, and the scratch
// schema has to be appended differently to each.
const (
	envTestURL = "TEST_DATABASE_URL"
	envTestDSN = "OLIVINE_TEST_DSN"
)

// withSearchPath appends the scratch schema to a connection
// string.
//
// The schema goes in the connection string and never a
// `SET search_path`: GORM pools connections, so a SET reaches
// whichever connection ran it and every other query lands in
// public. BOOTSTRAP.md §3.4 records this.
//
// A URL takes it as a query parameter and a key-value DSN as
// another space-separated pair. Appending " search_path=x" to a
// URL produces a connection string that silently ignores it, which
// is exactly the failure the rule exists to prevent.
func withSearchPath(dsn, schema string) string {
	if isURL(dsn) {
		return appendURLParam(dsn, "search_path", schema)
	}
	return dsn + " search_path=" + schema
}

// isURL reports whether a connection string is in URL form.
func isURL(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") ||
		strings.HasPrefix(dsn, "postgresql://")
}

// appendURLParam adds one query parameter to a URL.
func appendURLParam(raw, key, value string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// Not parseable as a URL after all; fall back to the
		// key-value form rather than returning something
		// that would connect to the wrong schema.
		return raw + " " + key + "=" + value
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}
