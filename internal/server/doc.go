// Package server accepts TLS connections and drives the
// operation lifecycle.
//
// Ported from servers/slapd/{daemon,connection}.c in the
// openldap submodule, with the poll loop replaced by a
// goroutine per connection.
//
// TLS only: no cleartext listener and no STARTTLS.
package server
